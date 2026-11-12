package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
)

func newTestConfig(t *testing.T) model.Config {
	t.Helper()

	config, _ := test.CreateTestConfigs(t)

	config.AppURL = "https://tinyauth.example.com"
	config.LabelProvider = "none"
	config.Auth.ACLs.Policy = "deny"
	config.Auth.Users = []string{"testuser:$2a$10$ne6z693sTgzT3ePoQ05PgOecUHnBjM7sSNj6M.l5CLUP.f6NyCnt."}
	config.Apps = map[string]model.App{
		"foo": {
			Config: model.AppConfig{Domain: "foo.example.com"},
			Path:   model.AppPath{Allow: "/.*"},
		},
	}
	config.OAuth.Providers = map[string]model.OAuthServiceConfig{
		"github": {ClientID: "client-id", ClientSecret: "client-secret"},
	}

	return config
}

func newTestApp(t *testing.T) (*BootstrapApp, model.Config) {
	t.Helper()

	log := logger.NewLogger().WithTestConfig()
	log.Init()

	config := newTestConfig(t)

	ctx, cancel := context.WithCancel(context.Background())

	app := NewBootstrapApp(config)
	app.ctx = ctx
	app.cancel = cancel
	app.log = log
	app.queries = memory.New()
	app.ding = ding.New(ctx)
	app.authCaches = service.NewAuthCaches()
	app.oidcCaches = service.NewOIDCCaches()

	inst, err := app.newInstance(config)
	require.NoError(t, err)

	app.setInstance(inst)
	inst.reconcile(ctx)

	t.Cleanup(func() {
		cancel()
		app.ding.Wait()
		app.currentInstance().shutdown()
	})

	return app, config
}

// allowed asks the app, as a proxy would, whether a request to the domain may go through
func allowed(app *BootstrapApp, domain string) bool {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/traefik", nil)
	req.Header.Set("X-Forwarded-Host", domain)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Uri", "/")

	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	return rec.Code == http.StatusOK
}

// startApp runs the setup as the command does, with a real listener, and
// waits for it to serve. The returned function shuts the app down with a
// SIGTERM and returns what the setup returned.
func startApp(t *testing.T, config model.Config, loader func() (model.Config, error)) (string, func() error) {
	t.Helper()

	// a SIGHUP that the app does not take must fail the test, not end the process
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(guard) })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().(*net.TCPAddr)
	require.NoError(t, listener.Close())

	config.Server.Address = address.IP.String()
	config.Server.Port = address.Port
	config.Database.Driver = "memory"
	config.Analytics.Enabled = false
	config.Log.Level = "disabled"

	app := NewBootstrapApp(config).WithConfigLoader(loader)
	returned := make(chan error, 1)

	go func() {
		returned <- app.Setup()
	}()

	var once sync.Once
	var result error

	stop := func() error {
		once.Do(func() {
			signalSelf(t, syscall.SIGTERM)

			select {
			case result = <-returned:
			case <-time.After(10 * time.Second):
				result = errors.New("setup did not return after SIGTERM")
			}

			app.cancel()
		})

		return result
	}

	t.Cleanup(func() { _ = stop() })

	base := "http://" + address.String()

	require.Eventually(t, func() bool {
		res, err := http.Get(base + "/api/healthz")
		if err != nil {
			return false
		}
		res.Body.Close()
		return res.StatusCode == http.StatusOK
	}, 15*time.Second, 20*time.Millisecond, "app did not start serving")

	return base, stop
}

func signalSelf(t *testing.T, sig os.Signal) {
	t.Helper()

	process, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, process.Signal(sig))
}

// allowedAt is allowed for an app that is serving on the given address. A
// request that fails counts as not allowed: the waits call this from a routine
// of their own, which must not fail the test and may still run when it is over.
func allowedAt(base string, domain string) bool {
	req, err := http.NewRequest(http.MethodGet, base+"/api/auth/traefik", nil)

	if err != nil {
		return false
	}

	req.Header.Set("X-Forwarded-Host", domain)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Uri", "/")

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return false
	}

	res.Body.Close()

	return res.StatusCode == http.StatusOK
}

// fakeKubernetes is the API of a cluster with one ingress, whose annotations
// allow any path of foo.example.com. The listing that loads the labels can be
// held back or made to fail.
type fakeKubernetes struct {
	mu   sync.Mutex
	hold chan struct{}
	fail bool
}

func (cluster *fakeKubernetes) set(hold chan struct{}, fail bool) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	cluster.hold = hold
	cluster.fail = fail
}

func (cluster *fakeKubernetes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const ingresses = `{"kind":"IngressList","apiVersion":"networking.k8s.io/v1","metadata":{"resourceVersion":"1"},"items":[` +
		`{"kind":"Ingress","apiVersion":"networking.k8s.io/v1","metadata":{"name":"foo","namespace":"default","annotations":` +
		`{"tinyauth.apps.foo.config.domain":"foo.example.com","tinyauth.apps.foo.path.allow":"/.*"}},` +
		`"spec":{"rules":[{"host":"foo.example.com"}]}}]}`

	failure := func(code int, reason string) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":%q,"code":%d}`, reason, code)
	}

	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query()

	switch {
	case r.URL.Path != "/apis/networking.k8s.io/v1/ingresses":
		failure(http.StatusNotFound, "NotFound")
	case query.Get("watch") != "":
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	case query.Get("limit") == "1":
		// the probe the service makes before it starts watching
		fmt.Fprint(w, ingresses)
	default:
		cluster.mu.Lock()
		hold, fail := cluster.hold, cluster.fail
		cluster.mu.Unlock()

		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}

		if fail {
			failure(http.StatusServiceUnavailable, "ServiceUnavailable")
			return
		}

		fmt.Fprint(w, ingresses)
	}
}

// useFakeKubernetes makes the kubernetes label provider talk to a fake cluster
func useFakeKubernetes(t *testing.T) *fakeKubernetes {
	t.Helper()

	cluster := &fakeKubernetes{}
	server := httptest.NewServer(cluster)

	// the watches are still open when the test ends, closing has to end them
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})

	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")

	require.NoError(t, os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: `+server.URL+`
  name: fake
contexts:
- context:
    cluster: fake
    user: fake
  name: fake
current-context: fake
users:
- name: fake
  user: {}
`), 0600))

	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	return cluster
}

// holdRequest sends the app a login whose body is not complete, so that the
// instance serving it keeps waiting, and returns the function that completes it
func holdRequest(t *testing.T, app *BootstrapApp) func() {
	t.Helper()

	reader, writer := io.Pipe()

	req := httptest.NewRequest(http.MethodPost, "/api/user/login", reader)
	req.Header.Set("Content-Type", "application/json")

	served := make(chan struct{})

	go func() {
		app.ServeHTTP(httptest.NewRecorder(), req)
		close(served)
	}()

	// the write returns once the handler has read it, so from then on the
	// request is being served
	written := make(chan error, 1)

	go func() {
		_, err := writer.Write([]byte(`{"username":"testuser",`))
		written <- err
	}()

	select {
	case err := <-written:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach the handler")
	}

	var once sync.Once

	finish := func() {
		once.Do(func() {
			_, _ = writer.Write([]byte(`"password":"wrong"}`))
			writer.Close()
			<-served
		})
	}

	t.Cleanup(finish)

	return finish
}

// stalledStore is a store that does not answer when its consents are listed,
// as a database that is locked or cannot be reached
type stalledStore struct {
	repository.Store
	asked chan struct{}
}

func (store *stalledStore) ListOIDCConsents(ctx context.Context) ([]repository.OidcConsent, error) {
	select {
	case store.asked <- struct{}{}:
	default:
	}

	<-ctx.Done()

	return nil, ctx.Err()
}

func stopped(inst *instance) bool {
	select {
	case <-inst.ctx.Done():
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

func TestSetup(t *testing.T) {
	t.Run("rejects an invalid configuration before the database is created", func(t *testing.T) {
		config, _ := test.CreateTestConfigs(t)

		config.AppURL = "invalid"
		config.Log.Level = "disabled"
		config.Database.Driver = "sqlite"
		config.Database.Path = filepath.Join(t.TempDir(), "data", "tinyauth.db")

		app := NewBootstrapApp(config)
		err := app.Setup()
		t.Cleanup(app.cancel)

		require.ErrorContains(t, err, "app url")
		assert.NoDirExists(t, filepath.Dir(config.Database.Path))
	})

	t.Run("reloads on SIGHUP and stops on SIGTERM", func(t *testing.T) {
		config := newTestConfig(t)

		reloaded := config
		reloaded.Apps = map[string]model.App{
			"bar": {
				Config: model.AppConfig{Domain: "bar.example.com"},
				Path:   model.AppPath{Allow: "/.*"},
			},
		}

		base, stop := startApp(t, config, func() (model.Config, error) {
			return reloaded, nil
		})

		require.True(t, allowedAt(base, "foo.example.com"))
		require.False(t, allowedAt(base, "bar.example.com"))

		signalSelf(t, syscall.SIGHUP)

		require.Eventually(t, func() bool {
			return allowedAt(base, "bar.example.com")
		}, 15*time.Second, 20*time.Millisecond, "app did not reload")

		assert.False(t, allowedAt(base, "foo.example.com"))
		assert.NoError(t, stop())
	})

	t.Run("keeps a SIGHUP that arrives while it starts", func(t *testing.T) {
		config := newTestConfig(t)

		reloaded := config
		reloaded.Apps = map[string]model.App{
			"bar": {
				Config: model.AppConfig{Domain: "bar.example.com"},
				Path:   model.AppPath{Allow: "/.*"},
			},
		}

		// a docker daemon that sends the signal when the app connects to it,
		// which is while the services are being built
		var once sync.Once

		docker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Api-Version", "1.45")
			w.Header().Set("Content-Type", "application/json")

			switch {
			case strings.HasSuffix(r.URL.Path, "/_ping"):
				once.Do(func() { signalSelf(t, syscall.SIGHUP) })
				_, _ = w.Write([]byte("OK"))
			case strings.HasSuffix(r.URL.Path, "/containers/json"):
				_, _ = w.Write([]byte("[]"))
			case strings.HasSuffix(r.URL.Path, "/events"):
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			default:
				http.NotFound(w, r)
			}
		}))

		t.Cleanup(docker.Close)
		t.Setenv("DOCKER_HOST", "tcp://"+docker.Listener.Addr().String())

		// the daemon above speaks plain HTTP, whatever the host is set up for
		t.Setenv("DOCKER_CERT_PATH", "")
		t.Setenv("DOCKER_TLS_VERIFY", "")

		config.LabelProvider = "docker"
		reloaded.LabelProvider = "docker"

		base, stop := startApp(t, config, func() (model.Config, error) {
			return reloaded, nil
		})

		require.Eventually(t, func() bool {
			return allowedAt(base, "bar.example.com")
		}, 15*time.Second, 20*time.Millisecond, "app did not reload")

		assert.NoError(t, stop())
	})
}

func TestNewInstance(t *testing.T) {
	t.Run("stops building when the app is shut down", func(t *testing.T) {
		app, config := newTestApp(t)

		// nothing listens here, so the LDAP service keeps trying to connect
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		config.LDAP.Address = "ldap://" + listener.Addr().String()
		require.NoError(t, listener.Close())

		built := make(chan error, 1)

		go func() {
			_, err := app.newInstance(config)
			built <- err
		}()

		// let the service start connecting
		time.Sleep(200 * time.Millisecond)
		app.cancel()

		select {
		case err := <-built:
			assert.ErrorContains(t, err, "failed to connect to ldap server")
		case <-time.After(2 * time.Second):
			t.Fatal("instance kept building after the app was shut down")
		}
	})
}

func TestReload(t *testing.T) {
	t.Run("serves the new configuration and stops the previous instance", func(t *testing.T) {
		app, config := newTestApp(t)
		previous := app.currentInstance()

		require.True(t, allowed(app, "foo.example.com"))
		require.False(t, allowed(app, "bar.example.com"))

		config.Apps = map[string]model.App{
			"bar": {
				Config: model.AppConfig{Domain: "bar.example.com"},
				Path:   model.AppPath{Allow: "/.*"},
			},
		}

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		require.NoError(t, app.reload())

		assert.NotSame(t, previous, app.currentInstance())
		assert.False(t, allowed(app, "foo.example.com"))
		assert.True(t, allowed(app, "bar.example.com"))
		assert.True(t, stopped(previous))
	})

	t.Run("keeps the instance when the configuration cannot be loaded", func(t *testing.T) {
		app, _ := newTestApp(t)
		previous := app.currentInstance()

		app.WithConfigLoader(func() (model.Config, error) {
			return model.Config{}, errors.New("invalid configuration")
		})

		require.ErrorContains(t, app.reload(), "invalid configuration")

		assert.Same(t, previous, app.currentInstance())
		assert.True(t, allowed(app, "foo.example.com"))
		assert.NoError(t, previous.ctx.Err())
	})

	t.Run("keeps the instance when the new one cannot be built", func(t *testing.T) {
		app, config := newTestApp(t)
		previous := app.currentInstance()

		config.LabelProvider = "invalid"

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		require.ErrorContains(t, app.reload(), "invalid label provider")

		assert.Same(t, previous, app.currentInstance())
		assert.True(t, allowed(app, "foo.example.com"))
		assert.NoError(t, previous.ctx.Err())
	})

	t.Run("keeps the stored data when the new instance fails late", func(t *testing.T) {
		app, config := newTestApp(t)
		ctx := context.Background()

		_, err := app.currentInstance().services.oidcService.UpsertOIDCConsent(ctx, "testuser", "openid", "some-client-id")
		require.NoError(t, err)

		// the client is gone and the router, which is set up last, fails
		config.OIDC.Clients = map[string]model.OIDCClientConfig{
			"other": {ClientID: "other-client-id", ClientSecret: "other-client-secret"},
		}
		config.Auth.TrustedProxies = []string{"invalid"}

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		require.ErrorContains(t, app.reload(), "failed to set trusted proxies")

		consents, err := app.queries.ListOIDCConsents(ctx)
		require.NoError(t, err)
		assert.Len(t, consents, 1)

		// once the configuration is accepted the consent is removed
		config.Auth.TrustedProxies = nil

		require.NoError(t, app.reload())

		consents, err = app.queries.ListOIDCConsents(ctx)
		require.NoError(t, err)
		assert.Empty(t, consents)
	})

	t.Run("keeps the instance and the stored data when the label provider is lost", func(t *testing.T) {
		app, config := newTestApp(t)
		previous := app.currentInstance()
		ctx := context.Background()

		// the reload would also remove a client that has a consent stored
		_, err := previous.services.oidcService.UpsertOIDCConsent(ctx, "testuser", "openid", "some-client-id")
		require.NoError(t, err)

		config.OIDC.Clients = map[string]model.OIDCClientConfig{
			"other": {ClientID: "other-client-id", ClientSecret: "other-client-secret"},
		}

		// the previous instance had a label provider, the new one cannot reach
		// it. Kubernetes without any configuration fails whatever the host runs.
		previous.services.kubernetesService = &service.KubernetesService{}
		config.LabelProvider = "kubernetes"
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		t.Setenv("KUBERNETES_SERVICE_PORT", "")
		t.Setenv("KUBERNETES_MASTER", "")
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		require.ErrorContains(t, app.reload(), "label provider is not available")

		assert.Same(t, previous, app.currentInstance())
		assert.NoError(t, previous.ctx.Err())

		consents, err := app.queries.ListOIDCConsents(ctx)
		require.NoError(t, err)
		assert.Len(t, consents, 1)
	})

	t.Run("waits for the labels of the new instance", func(t *testing.T) {
		app, config := newTestApp(t)
		cluster := useFakeKubernetes(t)

		// the only rule for foo.example.com is the one in the labels
		config.Apps = nil
		config.LabelProvider = "kubernetes"

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		require.NoError(t, app.reload())
		require.True(t, allowed(app, "foo.example.com"))

		// a reload while the cluster is slow to list its resources
		previous := app.currentInstance()
		hold := make(chan struct{})
		cluster.set(hold, false)

		reloaded := make(chan error, 1)

		go func() {
			reloaded <- app.reload()
		}()

		select {
		case <-reloaded:
			t.Fatal("reload did not wait for the labels")
		case <-time.After(300 * time.Millisecond):
		}

		assert.Same(t, previous, app.currentInstance())
		assert.True(t, allowed(app, "foo.example.com"))

		close(hold)

		select {
		case err := <-reloaded:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("reload did not finish once the labels were loaded")
		}

		assert.NotSame(t, previous, app.currentInstance())
		assert.True(t, allowed(app, "foo.example.com"))

		// a reload while the cluster fails to list its resources
		previous = app.currentInstance()
		cluster.set(nil, true)

		require.ErrorContains(t, app.reload(), "failed to load the labels")

		assert.Same(t, previous, app.currentInstance())
		assert.True(t, allowed(app, "foo.example.com"))
	})

	t.Run("waits for the requests of the previous instance", func(t *testing.T) {
		app, config := newTestApp(t)
		previous := app.currentInstance()

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		finish := holdRequest(t, app)

		require.NoError(t, app.reload())

		select {
		case <-previous.ctx.Done():
			t.Fatal("previous instance stopped while serving a request")
		case <-time.After(200 * time.Millisecond):
		}

		finish()

		assert.True(t, stopped(previous))
	})

	t.Run("stops the previous instance when its requests take too long", func(t *testing.T) {
		app, config := newTestApp(t)
		previous := app.currentInstance()

		app.drainTimeout = 300 * time.Millisecond

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		holdRequest(t, app)

		require.NoError(t, app.reload())

		select {
		case <-previous.ctx.Done():
			t.Fatal("previous instance stopped before its time was over")
		case <-time.After(100 * time.Millisecond):
		}

		assert.True(t, stopped(previous))
	})

	t.Run("keeps login attempts", func(t *testing.T) {
		app, config := newTestApp(t)

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		isLocked := func() bool {
			auth := app.currentInstance().services.authService
			locked := false

			err := auth.WithLoginAttempt("testuser", func(actions cache.CacheStoreActions[service.LoginAttempt]) error {
				locked, _ = auth.IsAccountLocked("testuser", actions)
				return nil
			})
			require.NoError(t, err)

			return locked
		}

		auth := app.currentInstance().services.authService

		for range config.Auth.LoginMaxRetries {
			err := auth.WithLoginAttempt("testuser", func(actions cache.CacheStoreActions[service.LoginAttempt]) error {
				auth.RecordLoginAttempt("testuser", false, actions)
				return nil
			})
			require.NoError(t, err)
		}

		require.True(t, isLocked())
		require.NoError(t, app.reload())
		assert.True(t, isLocked())
	})

	t.Run("keeps OIDC authorize requests in progress", func(t *testing.T) {
		app, config := newTestApp(t)

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		ticket := app.currentInstance().services.oidcService.CreateAuthorizeRequestTicket(service.AuthorizeRequest{
			ClientID: "some-client-id",
		})

		require.NoError(t, app.reload())

		req, ok := app.currentInstance().services.oidcService.GetAuthorizeRequestByTicket(ticket)
		require.True(t, ok)
		assert.Equal(t, "some-client-id", req.ClientID)
	})

	t.Run("keeps OAuth logins in progress while the provider is configured", func(t *testing.T) {
		app, config := newTestApp(t)

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		sessionId, err := app.currentInstance().services.authService.NewOAuthSession("github", service.OAuthCallbackParams{})
		require.NoError(t, err)

		require.NoError(t, app.reload())

		session, err := app.currentInstance().services.authService.GetOAuthPendingSession(sessionId)
		require.NoError(t, err)

		current, ok := app.currentInstance().services.oauthBrokerService.GetService("github")
		require.True(t, ok)
		assert.Same(t, current, session.Service)

		config.OAuth.Providers = nil

		require.NoError(t, app.reload())

		_, err = app.currentInstance().services.authService.GetOAuthPendingSession(sessionId)
		assert.ErrorContains(t, err, "oauth service no longer configured")
	})
}

func TestReloadRoutine(t *testing.T) {
	app, config := newTestApp(t)

	reloaded := config
	reloaded.Apps = map[string]model.App{
		"bar": {
			Config: model.AppConfig{Domain: "bar.example.com"},
			Path:   model.AppPath{Allow: "/.*"},
		},
	}

	loads := make(chan struct{}, 2)
	fail := true

	app.WithConfigLoader(func() (model.Config, error) {
		defer func() { loads <- struct{}{} }()
		if fail {
			fail = false
			return model.Config{}, errors.New("invalid configuration")
		}
		return reloaded, nil
	})

	ctx, stop := context.WithCancel(context.Background())
	sighup := make(chan os.Signal)
	done := make(chan struct{})

	go func() {
		app.reloadRoutine(ctx, sighup)
		close(done)
	}()

	// the first reload fails and the routine has to survive it
	for range 2 {
		select {
		case sighup <- syscall.SIGHUP:
		case <-done:
			t.Fatal("routine stopped after a failed reload")
		case <-time.After(5 * time.Second):
			t.Fatal("routine did not take the signal")
		}

		select {
		case <-loads:
		case <-time.After(5 * time.Second):
			t.Fatal("configuration was not loaded")
		}
	}

	stop()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("routine did not stop")
	}

	// the routine has returned, so the second reload is done
	assert.False(t, allowed(app, "foo.example.com"))
	assert.True(t, allowed(app, "bar.example.com"))
}

func TestReloadOnShutdown(t *testing.T) {
	t.Run("does not wait for an instance that is still connecting", func(t *testing.T) {
		app, config := newTestApp(t)

		// an LDAP server that accepts the connection and never answers, which
		// the LDAP client waits for whatever happens to its context
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		accepted := make(chan net.Conn, 16)

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					close(accepted)
					return
				}
				accepted <- conn
			}
		}()

		t.Cleanup(func() {
			listener.Close()
			for conn := range accepted {
				conn.Close()
			}
		})

		config.LDAP.Address = "ldap://" + listener.Addr().String()

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		previous := app.currentInstance()
		reloaded := make(chan error, 1)

		go func() {
			reloaded <- app.reload()
		}()

		// let the service connect
		time.Sleep(200 * time.Millisecond)
		app.cancel()

		select {
		case err := <-reloaded:
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(2 * time.Second):
			t.Fatal("reload held the shutdown")
		}

		assert.Same(t, previous, app.currentInstance())
	})

	t.Run("does not wait for a database that does not answer", func(t *testing.T) {
		app, config := newTestApp(t)

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		// from here on the stored consents are never listed
		store := &stalledStore{Store: app.queries, asked: make(chan struct{}, 1)}
		app.queries = store

		reloaded := make(chan error, 1)

		go func() {
			reloaded <- app.reload()
		}()

		select {
		case <-store.asked:
		case <-time.After(5 * time.Second):
			t.Fatal("reload did not get to the stored consents")
		}

		app.cancel()

		select {
		case <-reloaded:
		case <-time.After(2 * time.Second):
			t.Fatal("reload held the shutdown")
		}
	})

	t.Run("ignores a signal that is still pending", func(t *testing.T) {
		app, config := newTestApp(t)
		loads := 0

		app.WithConfigLoader(func() (model.Config, error) {
			loads++
			return config, nil
		})

		ctx, stop := context.WithCancel(context.Background())
		stop()

		// which of the two the routine sees first is random, so try a few times
		for range 20 {
			sighup := make(chan os.Signal, 1)
			sighup <- syscall.SIGHUP

			app.reloadRoutine(ctx, sighup)
		}

		assert.Zero(t, loads)
	})
}

func TestRestartRequired(t *testing.T) {
	app, config := newTestApp(t)

	assert.False(t, app.restartRequired(config))

	changed := config
	changed.Apps = nil
	changed.Auth.LoginMaxRetries = 10
	assert.False(t, app.restartRequired(changed))

	changed = config
	changed.Server.Port = 8080
	assert.True(t, app.restartRequired(changed))

	changed = config
	changed.Database.Path = "/other.db"
	assert.True(t, app.restartRequired(changed))

	changed = config
	changed.Log.Level = "debug"
	assert.True(t, app.restartRequired(changed))

	changed = config
	changed.Analytics.Enabled = !config.Analytics.Enabled
	assert.True(t, app.restartRequired(changed))
}
