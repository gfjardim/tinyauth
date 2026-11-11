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
	config   model.Config
	log      *logger.Logger
	ctx      context.Context
	cancel   context.CancelFunc
	queries  repository.Store
	db       *sql.DB
	ding     *ding.Ding
	instance *instance
}

func NewBootstrapApp(config model.Config) *BootstrapApp {
	return &BootstrapApp{
		config: config,
	}
}

func (app *BootstrapApp) Setup() error {
	// create context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	app.ctx = ctx
	app.cancel = cancel

	// create a ding instance
	dg := ding.New(ctx)
	app.ding = dg

	// setup logger
	log := logger.NewLogger().WithConfig(app.config.Log)
	log.Init()
	app.log = log

	app.log.App.Info().Msgf("Starting Tinyauth version: %s", model.Version)

	// database
	store, err := app.SetupStore()

	if err != nil {
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

	// build everything that depends on the configuration
	inst, err := app.newInstance(app.config)

	if err != nil {
		return err
	}

	app.instance = inst

	// start db cleanup routine
	app.log.App.Debug().Msg("Starting database cleanup routine")
	app.ding.Go(app.dbCleanupRoutine, ding.RingMinor)

	// if analytics are not disabled, start heartbeat
	if app.config.Analytics.Enabled {
		app.log.App.Debug().Msg("Starting heartbeat routine")
		app.ding.Go(app.heartbeatRoutine, ding.RingMinor)
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

func (app *BootstrapApp) heartbeatRoutine(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(12) * time.Hour)
	defer ticker.Stop()

	type Heartbeat struct {
		UUID    string `json:"uuid"`
		Version string `json:"version"`
	}

	var body Heartbeat

	body.UUID = app.instance.runtime.UUID
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
