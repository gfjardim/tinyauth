package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path"
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

// syncBuffer collects what the logger writes, which comes from several routines
type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

// sendSelf sends a signal to the process of the test
func sendSelf(sig os.Signal) error {
	process, err := os.FindProcess(os.Getpid())

	if err != nil {
		return err
	}

	return process.Signal(sig)
}

func signalSelf(t *testing.T, sig os.Signal) {
	t.Helper()

	require.NoError(t, sendSelf(sig))
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
//
// The cluster can also be given the applications resource, with one
// application that allows any path of bar.example.com. The probe of that
// resource, the request the service makes before it watches a resource, can
// be held back or made to fail.
type fakeKubernetes struct {
	mu   sync.Mutex
	hold chan struct{}
	fail bool

	applications bool
	holdProbe    chan struct{}
	failProbe    int

	// gets "probe" or "list" and the name of the resource when a probe or a
	// listing that loads the labels arrives
	requests chan string
}

func (cluster *fakeKubernetes) set(hold chan struct{}, fail bool) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	cluster.hold = hold
	cluster.fail = fail
}

// setApplications gives the cluster the applications resource. The probe of
// the resource waits for hold, if any, and fails with the given status code,
// if any.
func (cluster *fakeKubernetes) setApplications(hold chan struct{}, fail int) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	cluster.applications = true
	cluster.holdProbe = hold
	cluster.failProbe = fail
}

func (cluster *fakeKubernetes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const ingresses = `{"kind":"IngressList","apiVersion":"networking.k8s.io/v1","metadata":{"resourceVersion":"1"},"items":[` +
		`{"kind":"Ingress","apiVersion":"networking.k8s.io/v1","metadata":{"name":"foo","namespace":"default","annotations":` +
		`{"tinyauth.apps.foo.config.domain":"foo.example.com","tinyauth.apps.foo.path.allow":"/.*"}},` +
		`"spec":{"rules":[{"host":"foo.example.com"}]}}]}`

	const applications = `{"kind":"ApplicationList","apiVersion":"tinyauth.app/v1alpha1","metadata":{"resourceVersion":"1"},"items":[` +
		`{"kind":"Application","apiVersion":"tinyauth.app/v1alpha1","metadata":{"name":"bar","namespace":"default"},` +
		`"spec":{"config":{"domain":"bar.example.com"},"path":{"allow":"/.*"}}}]}`

	failure := func(code int) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":%q,"code":%d}`,
			strings.ReplaceAll(http.StatusText(code), " ", ""), code)
	}

	// waits for the channel, if any, and reports whether the request is still there
	wait := func(hold chan struct{}) bool {
		if hold == nil {
			return true
		}

		select {
		case <-hold:
			return true
		case <-r.Context().Done():
			return false
		}
	}

	arrived := func(request string) {
		select {
		case cluster.requests <- request + " " + path.Base(r.URL.Path):
		default:
		}
	}

	cluster.mu.Lock()
	hold, fail := cluster.hold, cluster.fail
	hasApplications, holdProbe, failProbe := cluster.applications, cluster.holdProbe, cluster.failProbe
	cluster.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	var items string

	switch {
	case r.URL.Path == "/apis/networking.k8s.io/v1/ingresses":
		items = ingresses
		holdProbe, failProbe = nil, 0
	case r.URL.Path == "/apis/tinyauth.app/v1alpha1/applications" && hasApplications:
		items = applications
	default:
		failure(http.StatusNotFound)
		return
	}

	query := r.URL.Query()

	switch {
	case query.Get("watch") != "":
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	case query.Get("limit") == "1":
		// the probe the service makes before it starts watching
		arrived("probe")

		if !wait(holdProbe) {
			return
		}

		if failProbe != 0 {
			failure(failProbe)
			return
		}

		fmt.Fprint(w, items)
	default:
		arrived("list")

		if !wait(hold) {
			return
		}

		if fail {
			failure(http.StatusServiceUnavailable)
			return
		}

		fmt.Fprint(w, items)
	}
}

// useFakeKubernetes makes the kubernetes label provider talk to a fake cluster
func useFakeKubernetes(t *testing.T) *fakeKubernetes {
	t.Helper()

	cluster := &fakeKubernetes{requests: make(chan string, 16)}
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
				// a handler may not fail the test. A signal that was not
				// sent shows as the reload that does not come.
				once.Do(func() { _ = sendSelf(syscall.SIGHUP) })
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

	t.Run("does not follow the context of the app once it is built", func(t *testing.T) {
		app, _ := newTestApp(t)
		inst := app.currentInstance()

		// a routine of the instance, as its services start them
		ended := make(chan struct{})

		inst.ding.Go(func(ctx context.Context) {
			<-ctx.Done()
			close(ended)
		}, ding.RingMajor)

		app.cancel()

		// the app stops its listener first and shuts the instance down after
		select {
		case <-inst.ctx.Done():
			t.Fatal("instance was stopped by the context of the app")
		case <-ended:
			t.Fatal("routines of the instance were stopped by the context of the app")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("keeps its routines until it is shut down", func(t *testing.T) {
		app, config := newTestApp(t)

		inst, err := app.prepareInstance(config)
		require.NoError(t, err)

		ended := make(chan struct{})

		inst.ding.Go(func(ctx context.Context) {
			<-ctx.Done()
			close(ended)
		}, ding.RingMajor)

		// what the shutdown of the app does to an instance that is being built
		inst.cancel(context.Canceled)

		select {
		case <-ended:
			t.Fatal("routine was stopped while the instance was still being built")
		case <-time.After(200 * time.Millisecond):
		}

		inst.shutdown()

		select {
		case <-ended:
		default:
			t.Fatal("routine was not stopped by the shutdown")
		}
	})
}

func TestKubernetesLabels(t *testing.T) {
	t.Run("are loaded for a resource while the next one is still probed", func(t *testing.T) {
		app, config := newTestApp(t)
		cluster := useFakeKubernetes(t)

		// the service looks at the applications after the ingresses
		hold := make(chan struct{})
		cluster.setApplications(hold, 0)

		config.LabelProvider = "kubernetes"

		built := make(chan *instance, 1)

		go func() {
			inst, _ := app.newInstance(config)
			built <- inst
		}()

		var release sync.Once

		t.Cleanup(func() {
			release.Do(func() { close(hold) })

			if inst := <-built; inst != nil {
				inst.shutdown()
			}
		})

		// the probe gives up after 10 seconds, the listing has to come before
		var probing <-chan time.Time

		limit := time.After(30 * time.Second)

		for listed := false; !listed; {
			select {
			case request := <-cluster.requests:
				switch request {
				case "probe applications":
					probing = time.After(5 * time.Second)
				case "list ingresses":
					listed = true
				}
			case <-probing:
				t.Fatal("labels of the ingresses were not loaded while the applications were probed")
			case <-limit:
				t.Fatal("service did not get to the cluster")
			}
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
		case <-time.After(15 * time.Second):
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

	t.Run("keeps the instance when a resource of the cluster cannot be probed", func(t *testing.T) {
		app, config := newTestApp(t)
		cluster := useFakeKubernetes(t)
		cluster.setApplications(nil, 0)

		// the only rules are the ones in the labels
		config.Apps = nil
		config.LabelProvider = "kubernetes"

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		require.NoError(t, app.reload())
		require.True(t, allowed(app, "foo.example.com"))
		require.True(t, allowed(app, "bar.example.com"))

		// a reload while the cluster fails to answer for the applications
		previous := app.currentInstance()
		cluster.setApplications(nil, http.StatusServiceUnavailable)

		require.ErrorContains(t, app.reload(), "failed to load the labels")

		assert.Same(t, previous, app.currentInstance())
		assert.True(t, allowed(app, "bar.example.com"))

		// applications that the app may not read are left out, as when it starts
		cluster.setApplications(nil, http.StatusForbidden)

		require.NoError(t, app.reload())

		assert.True(t, allowed(app, "foo.example.com"))
		assert.False(t, allowed(app, "bar.example.com"))
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

		// the time it gets unless a test shortens it
		require.Equal(t, model.GracefulShutdownTimeout*time.Second, app.drainTimeout)

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

	output := &syncBuffer{}
	log := logger.NewLogger().WithTestConfig().WithWriter(output)
	log.Init()
	app.log = log

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
		case <-time.After(15 * time.Second):
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
	case <-time.After(15 * time.Second):
		t.Fatal("routine did not stop")
	}

	// the routine has returned, so the second reload is done
	assert.False(t, allowed(app, "foo.example.com"))
	assert.True(t, allowed(app, "bar.example.com"))

	// the first one was reported
	assert.Contains(t, output.String(), "Failed to reload configuration")
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

	t.Run("stops an instance that gets ready after the reload gave up", func(t *testing.T) {
		app, config := newTestApp(t)

		// an LDAP server that only answers the bind when it is told to, finds
		// nothing in a search and reports when the app closes the connection
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { listener.Close() })

		asked := make(chan struct{})
		answer := make(chan struct{})
		closed := make(chan struct{})

		go func() {
			conn, err := listener.Accept()

			if err != nil {
				return
			}

			defer conn.Close()

			buffer := make([]byte, 1024)

			if _, err := conn.Read(buffer); err != nil {
				return
			}

			close(asked)
			<-answer

			// a bind response with the result success, for the first message
			_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})

			for {
				read, err := conn.Read(buffer)

				if err != nil {
					close(closed)
					return
				}

				// a search, answered as done with the result success
				if read > 5 && buffer[5] == 0x63 {
					_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, buffer[4], 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
				}
			}
		}()

		var release sync.Once

		t.Cleanup(func() {
			release.Do(func() { close(answer) })
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

		select {
		case <-asked:
		case <-time.After(15 * time.Second):
			t.Fatal("instance did not connect to the LDAP server")
		}

		app.cancel()

		select {
		case err := <-reloaded:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(2 * time.Second):
			t.Fatal("reload held the shutdown")
		}

		// the instance is now built without anyone waiting for it
		release.Do(func() { close(answer) })

		select {
		case <-closed:
		case <-time.After(15 * time.Second):
			t.Fatal("instance was left running")
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

		// started as the app starts it. The reload goes on to retire the
		// previous instance, which the app only stops waiting for once the
		// routine of the reload has returned.
		app.ding.Go(func(context.Context) {
			reloaded <- app.reload()
		}, ding.RingMinor)

		select {
		case <-store.asked:
		case <-time.After(15 * time.Second):
			t.Fatal("reload did not get to the stored consents")
		}

		app.cancel()

		select {
		case <-reloaded:
		case <-time.After(2 * time.Second):
			t.Fatal("reload held the shutdown")
		}
	})

	t.Run("ignores a signal that arrives with the shutdown", func(t *testing.T) {
		app, config := newTestApp(t)
		loads := 0

		app.WithConfigLoader(func() (model.Config, error) {
			loads++
			return config, nil
		})

		// the context of the app is cancelled first, the one of the routine
		// only once the app gets to stopping it
		app.cancel()

		ctx, stop := context.WithCancel(context.Background())
		sighup := make(chan os.Signal)
		done := make(chan struct{})

		go func() {
			app.reloadRoutine(ctx, sighup)
			close(done)
		}()

		select {
		case sighup <- syscall.SIGHUP:
		case <-time.After(5 * time.Second):
			t.Fatal("routine did not take the signal")
		}

		stop()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("routine did not stop")
		}

		assert.Zero(t, loads)
	})

	t.Run("does not report a reload that the shutdown interrupted as failed", func(t *testing.T) {
		app, config := newTestApp(t)

		output := &syncBuffer{}
		log := logger.NewLogger().WithTestConfig().WithWriter(output)
		log.Init()
		app.log = log

		// the shutdown arrives behind the signal, once the routine has
		// taken it and is loading the configuration
		app.WithConfigLoader(func() (model.Config, error) {
			app.cancel()
			return config, nil
		})

		ctx, stop := context.WithCancel(context.Background())
		sighup := make(chan os.Signal)
		done := make(chan struct{})

		go func() {
			app.reloadRoutine(ctx, sighup)
			close(done)
		}()

		select {
		case sighup <- syscall.SIGHUP:
		case <-time.After(5 * time.Second):
			t.Fatal("routine did not take the signal")
		}

		stop()

		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("routine did not stop")
		}

		assert.Contains(t, output.String(), "Received SIGHUP, reloading configuration")
		assert.NotContains(t, output.String(), "Failed to reload configuration")
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
