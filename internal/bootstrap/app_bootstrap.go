package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/steveiliop56/ding"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

// Shutdown order for go routines
// 1. Janitor routines (e.g. database cleanup, heartbeat) - ding.RingMinor
// 2. HTTP server listeners - ding.RingNormal
// 3. Networking layers, user and label providers (e.g. ailscale service, kubernetes service) - ding.RingMajor
// 4. Database connection - ding.RingCritical
//
// The routines started by the services run in the ding of their instance, which
// follows the same order and is shut down by the app in step 3

type Services struct {
	accessControlService *service.AccessControlsService
	authService          *service.AuthService
	dockerService        *service.DockerService
	kubernetesService    *service.KubernetesService
	ldapService          *service.LdapService
	oauthBrokerService   *service.OAuthBrokerService
	oidcService          *service.OIDCService
	tailscaleService     *service.TailscaleService
	policyEngine         *service.PolicyEngine
}

type BootstrapApp struct {
	config  model.Config
	log     *logger.Logger
	ctx     context.Context
	cancel  context.CancelFunc
	queries repository.Store
	db      *sql.DB
	ding    *ding.Ding

	// in-memory state of the services that outlives an instance
	authCaches *service.AuthCaches
	oidcCaches *service.OIDCCaches

	// instance serving the requests, guarded by mu
	instance *instance
	mu       sync.RWMutex

	// how long an instance that was replaced may take to finish its requests
	drainTimeout time.Duration

	// loads the configuration again from its sources, nil disables reloading
	configLoader func() (model.Config, error)
}

func NewBootstrapApp(config model.Config) *BootstrapApp {
	return &BootstrapApp{
		config:       config,
		drainTimeout: model.GracefulShutdownTimeout * time.Second,
	}
}

// WithConfigLoader enables reloading on SIGHUP, with the configuration
// returned by the given loader
func (app *BootstrapApp) WithConfigLoader(loader func() (model.Config, error)) *BootstrapApp {
	app.configLoader = loader
	return app
}

func (app *BootstrapApp) Setup() error {
	// create context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	app.ctx = ctx
	app.cancel = cancel

	// take SIGHUP over before anything else, so that it does not end the app
	// while it starts. A signal that arrives meanwhile is kept for the reload
	// routine.
	var sighup chan os.Signal

	if app.configLoader != nil {
		sighup = make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		defer signal.Stop(sighup)
	}

	// create a ding instance
	dg := ding.New(ctx)
	app.ding = dg

	// setup logger
	log := logger.NewLogger().WithConfig(app.config.Log)
	log.Init()
	app.log = log

	app.log.App.Info().Msgf("Starting Tinyauth version: %s", model.Version)

	// an invalid configuration is found here, before anything is created
	inst, err := app.prepareInstance(app.config)

	if err != nil {
		return err
	}

	// database
	store, err := app.SetupStore()

	if err != nil {
		inst.shutdown()
		return fmt.Errorf("failed to setup database: %w", err)
	}

	app.ding.Go(func(ctx context.Context) {
		<-ctx.Done()
		app.log.App.Debug().Msg("Shutting down database connection")
		if app.db == nil {
			// using memory store, no db instance
			return
		}
		if err := app.db.Close(); err != nil {
			app.log.App.Error().Err(err).Msg("Failed to close database connection")
		}
	}, ding.RingCritical)

	// store
	app.queries = store

	// state that outlives an instance
	app.authCaches = service.NewAuthCaches()
	app.oidcCaches = service.NewOIDCCaches()

	// build everything that depends on the configuration
	err = app.startInstance(inst)

	if err != nil {
		return err
	}

	app.setInstance(inst)
	inst.reconcile(app.ctx)

	app.ding.Go(func(ctx context.Context) {
		<-ctx.Done()
		app.log.App.Debug().Msg("Shutting down services")
		app.currentInstance().shutdown()
	}, ding.RingMajor)

	// start db cleanup routine
	app.log.App.Debug().Msg("Starting database cleanup routine")
	app.ding.Go(app.dbCleanupRoutine, ding.RingMinor)

	// if analytics are not disabled, start heartbeat
	if app.config.Analytics.Enabled {
		app.log.App.Debug().Msg("Starting heartbeat routine")
		app.ding.Go(app.heartbeatRoutine, ding.RingMinor)
	}

	// reload the configuration on SIGHUP
	if app.configLoader != nil {
		app.ding.Go(func(ctx context.Context) {
			app.reloadRoutine(ctx, sighup)
		}, ding.RingMinor)
	}

	// get listener
	listenerFunc, err := app.getListenerFunc()

	if err != nil {
		return fmt.Errorf("failed to get listener function: %w", err)
	}

	// run listener
	lec := make(chan error, 1)

	app.ding.Go(func(ctx context.Context) {
		lec <- listenerFunc(ctx)
	}, ding.RingNormal)

	// monitor cancellation and server errors
	for {
		select {
		case <-app.ctx.Done():
			app.ding.Wait()
			app.log.App.Info().Msg("Oh, it's time for me to go, bye!")
			return nil
		case err := <-lec:
			if err != nil {
				return fmt.Errorf("listener error: %w", err)
			}
		}
	}
}

func (app *BootstrapApp) currentInstance() *instance {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.instance
}

// setInstance makes the given instance serve the requests and returns the previous one
func (app *BootstrapApp) setInstance(inst *instance) *instance {
	app.mu.Lock()
	defer app.mu.Unlock()
	previous := app.instance
	app.instance = inst
	return previous
}

// ServeHTTP hands the request to the current instance
func (app *BootstrapApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// count the request while holding the lock, so an instance that has been
	// replaced never gets a new request
	app.mu.RLock()
	inst := app.instance
	inst.requests.Add(1)
	app.mu.RUnlock()

	defer inst.requests.Done()

	inst.router.ServeHTTP(w, r)
}

// reload builds a new instance from the configuration returned by the loader
// and makes it serve the requests. If the configuration cannot be loaded or
// the instance cannot be built, the current instance is left untouched.
func (app *BootstrapApp) reload() error {
	config, err := app.configLoader()

	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	inst, err := app.newInstanceUntilShutdown(config)

	if err != nil {
		return fmt.Errorf("failed to apply configuration: %w", err)
	}

	// the instance is accepted, from here on the reload cannot fail
	previous := app.setInstance(inst)
	inst.reconcile(app.ctx)
	app.retire(previous)

	if app.restartRequired(config) {
		app.log.App.Warn().Msg("Changes to the server, database, log and analytics configuration are only applied on restart")
	}

	return nil
}

// newInstanceUntilShutdown builds an instance, but gives up when the app is
// shut down meanwhile. A shutdown interrupts the services that follow their
// context, the others would hold it until they are done connecting.
func (app *BootstrapApp) newInstanceUntilShutdown(config model.Config) (*instance, error) {
	type result struct {
		inst *instance
		err  error
	}

	built := make(chan result, 1)

	go func() {
		inst, err := app.newInstance(config)
		built <- result{inst, err}
	}()

	select {
	case res := <-built:
		if res.err == nil && app.ctx.Err() != nil {
			res.inst.shutdown()
			return nil, context.Cause(app.ctx)
		}

		return res.inst, res.err
	case <-app.ctx.Done():
		// whatever is still connecting is stopped once it returns
		go func() {
			if res := <-built; res.err == nil {
				res.inst.shutdown()
			}
		}()

		return nil, context.Cause(app.ctx)
	}
}

// restartRequired reports whether the given configuration changes something
// that is only set up once, when the app starts
func (app *BootstrapApp) restartRequired(config model.Config) bool {
	return config.Server != app.config.Server ||
		config.Database != app.config.Database ||
		config.Log != app.config.Log ||
		config.Analytics != app.config.Analytics
}

// retire shuts an instance down once it has served the requests it already had
func (app *BootstrapApp) retire(inst *instance) {
	app.ding.Go(func(ctx context.Context) {
		served := make(chan struct{})

		go func() {
			inst.requests.Wait()
			close(served)
		}()

		select {
		case <-served:
		case <-time.After(app.drainTimeout):
			app.log.App.Warn().Msg("Previous configuration is still serving requests, shutting its services down anyway")
		case <-ctx.Done():
		}

		inst.shutdown()
	}, ding.RingMajor)
}

func (app *BootstrapApp) reloadRoutine(ctx context.Context, sighup <-chan os.Signal) {
	for {
		select {
		case <-sighup:
			// a signal that arrives with the shutdown. The context of the
			// app is looked at because the one of the routine is only
			// cancelled a moment later.
			if app.ctx.Err() != nil {
				continue
			}

			app.log.App.Info().Msg("Received SIGHUP, reloading configuration")

			if err := app.reload(); err != nil {
				// a reload that the shutdown interrupted was not refused
				if app.ctx.Err() != nil {
					app.log.App.Debug().Err(err).Msg("Configuration reload interrupted by the shutdown")
					continue
				}

				app.log.App.Error().Err(err).Msg("Failed to reload configuration, keeping the previous one")
				continue
			}

			app.log.App.Info().Msg("Configuration reloaded")
		case <-ctx.Done():
			app.log.App.Debug().Msg("Stopping configuration reload routine")
			return
		}
	}
}

func (app *BootstrapApp) heartbeatRoutine(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(12) * time.Hour)
	defer ticker.Stop()

	type Heartbeat struct {
		UUID    string `json:"uuid"`
		Version string `json:"version"`
	}

	var body Heartbeat

	body.UUID = app.currentInstance().runtime.UUID
	body.Version = model.Version

	bodyJson, err := json.Marshal(body)

	if err != nil {
		app.log.App.Error().Err(err).Msg("Failed to marshal heartbeat body, heartbeat routine will not start")
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second, // The server should never take more than 30 seconds to respond
	}

	heartbeatURL := model.APIServer + "/v1/instances/heartbeat"

	for {
		select {
		case <-ticker.C:
			app.log.App.Debug().Msg("Sending heartbeat")

			req, err := http.NewRequest(http.MethodPost, heartbeatURL, bytes.NewReader(bodyJson))

			if err != nil {
				app.log.App.Error().Err(err).Msg("Failed to create heartbeat request")
				continue
			}

			req.Header.Add("Content-Type", "application/json")

			res, err := client.Do(req)

			if err != nil {
				app.log.App.Error().Err(err).Msg("Failed to send heartbeat")
				continue
			}

			res.Body.Close()

			if res.StatusCode != 200 && res.StatusCode != 201 {
				app.log.App.Debug().Str("status", res.Status).Msg("Heartbeat returned non-200/201 status")
			}
		case <-ctx.Done():
			app.log.App.Debug().Msg("Stopping heartbeat routine")
			ticker.Stop()
			return
		}
	}
}

func (app *BootstrapApp) dbCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(30) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			app.log.App.Debug().Msg("Running database cleanup")

			err := app.queries.DeleteExpiredSessions(ctx, time.Now().Unix())

			if err != nil {
				app.log.App.Error().Err(err).Msg("Failed to delete expired sessions")
			}

			app.log.App.Debug().Msg("Database cleanup completed")
		case <-ctx.Done():
			app.log.App.Debug().Msg("Stopping database cleanup routine")
			ticker.Stop()
			return
		}
	}
}
