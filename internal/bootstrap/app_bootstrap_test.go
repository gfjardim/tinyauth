package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/test"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
)

func newTestApp(t *testing.T) (*BootstrapApp, model.Config) {
	t.Helper()

	log := logger.NewLogger().WithTestConfig()
	log.Init()

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

func stopped(inst *instance) bool {
	select {
	case <-inst.ctx.Done():
		return true
	case <-time.After(2 * time.Second):
		return false
	}
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

	t.Run("keeps the instance when the label provider is lost", func(t *testing.T) {
		app, config := newTestApp(t)
		previous := app.currentInstance()

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
	})

	t.Run("waits for the requests of the previous instance", func(t *testing.T) {
		app, config := newTestApp(t)
		previous := app.currentInstance()

		app.WithConfigLoader(func() (model.Config, error) {
			return config, nil
		})

		// a request still being served
		previous.requests.Add(1)

		require.NoError(t, app.reload())

		select {
		case <-previous.ctx.Done():
			t.Fatal("previous instance stopped while serving a request")
		case <-time.After(200 * time.Millisecond):
		}

		previous.requests.Done()

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
