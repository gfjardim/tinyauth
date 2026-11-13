package bootstrap

import (
	"context"
	"net"
	"path/filepath"
	"sync"
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

	inst, err := app.prepareInstance(config)
	require.NoError(t, err)
	require.NoError(t, app.startInstance(inst))

	app.setInstance(inst)
	inst.reconcile(ctx)

	t.Cleanup(func() {
		cancel()
		app.ding.Wait()
		app.currentInstance().shutdown()
	})

	return app, config
}

// fakeLDAP is an LDAP server that only answers the bind when it is told to
// and finds nothing in a search
type fakeLDAP struct {
	address string
	// closed when the bind has arrived
	asked chan struct{}
	// lets the server answer the bind
	answer func()
}

func useFakeLDAP(t *testing.T) *fakeLDAP {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	hold := make(chan struct{})

	var release sync.Once

	server := &fakeLDAP{
		address: "ldap://" + listener.Addr().String(),
		asked:   make(chan struct{}),
		answer:  func() { release.Do(func() { close(hold) }) },
	}

	t.Cleanup(server.answer)

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

		close(server.asked)
		<-hold

		// a bind response with the result success, for the first message
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})

		for {
			read, err := conn.Read(buffer)

			if err != nil {
				return
			}

			// a search, answered as done with the result success
			if read > 5 && buffer[5] == 0x63 {
				_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, buffer[4], 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
			}
		}
	}()

	return server
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
			inst, err := app.prepareInstance(config)

			if err == nil {
				err = app.startInstance(inst)
			}

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

	t.Run("keeps its routines when the app is shut down while it is built", func(t *testing.T) {
		app, config := newTestApp(t)

		// the bind holds the build until the server is told to answer
		server := useFakeLDAP(t)
		config.LDAP.Address = server.address

		inst, err := app.prepareInstance(config)
		require.NoError(t, err)

		ended := make(chan struct{})

		inst.ding.Go(func(ctx context.Context) {
			<-ctx.Done()
			close(ended)
		}, ding.RingMajor)

		started := make(chan error, 1)

		go func() {
			started <- app.startInstance(inst)
		}()

		select {
		case <-server.asked:
		case <-time.After(15 * time.Second):
			t.Fatal("instance did not connect to the LDAP server")
		}

		app.cancel()

		// the services that are still to be built add routines, which a
		// ding that is stopping cannot take
		select {
		case <-ended:
			t.Fatal("routine was stopped while the instance was still being built")
		case <-time.After(200 * time.Millisecond):
		}

		server.answer()

		select {
		case err := <-started:
			// an instance that got built is stopped by whoever asked for it
			if err == nil {
				inst.shutdown()
			}
		case <-time.After(15 * time.Second):
			t.Fatal("build did not return")
		}

		select {
		case <-ended:
		default:
			t.Fatal("routine was not stopped by the shutdown")
		}
	})
}
