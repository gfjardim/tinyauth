package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/ding"
	"go.uber.org/dig"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

// instance holds everything that is built from one configuration: the
// runtime config, the services and the router
type instance struct {
	config   model.Config
	runtime  model.RuntimeConfig
	services Services
	log      *logger.Logger
	ctx      context.Context
	cancel   context.CancelCauseFunc
	queries  repository.Store
	router   *gin.Engine
	ding     *ding.Ding
	dig      *dig.Container

	// stops the routines in the ding, which have a context of their own
	stopRoutines context.CancelFunc

	authCaches *service.AuthCaches
	oidcCaches *service.OIDCCaches

	// requests being served by this instance
	requests sync.WaitGroup
}

// newInstance prepares an instance for the configuration and starts it
func (app *BootstrapApp) newInstance(config model.Config) (*instance, error) {
	inst, err := app.prepareInstance(config)

	if err != nil {
		return nil, err
	}

	if err := app.startInstance(inst); err != nil {
		return nil, err
	}

	return inst, nil
}

// prepareInstance creates an instance and derives its runtime config, which is
// where an invalid configuration is found. It opens no connection and stores
// nothing, so it can run before the database is set up.
func (app *BootstrapApp) prepareInstance(config model.Config) (*instance, error) {
	// once it is built the instance does not follow the app context, the app
	// shuts it down after the listener has stopped
	detached := context.WithoutCancel(app.ctx)
	ctx, cancel := context.WithCancelCause(detached)

	// the context of the services is cancelled when the app is shut down
	// while they are being built. The routines must not stop with it: a ding
	// that is stopping while routines are still added to it can panic.
	routines, stopRoutines := context.WithCancel(detached)

	inst := &instance{
		config:       config,
		log:          app.log,
		ctx:          ctx,
		cancel:       cancel,
		ding:         ding.New(routines),
		dig:          dig.New(),
		stopRoutines: stopRoutines,
	}

	err := inst.setupRuntime()

	if err != nil {
		inst.shutdown()
		return nil, err
	}

	return inst, nil
}

// startInstance builds the services and the router of a prepared instance
func (app *BootstrapApp) startInstance(inst *instance) error {
	inst.queries = app.queries
	inst.authCaches = app.authCaches
	inst.oidcCaches = app.oidcCaches

	// while it is being built the instance follows the app context, so that a
	// shutdown does not have to wait for services that cannot connect
	stop := context.AfterFunc(app.ctx, func() {
		inst.cancel(context.Cause(app.ctx))
	})

	err := inst.setup()

	stop()

	if err != nil {
		inst.shutdown()
		return err
	}

	return nil
}

// reconcile brings the stored data in line with the configuration of the
// instance. An instance can still be rejected after it has been built, so this
// is only to be called once the instance has been accepted. It runs on the
// given context and not on the one of the instance, which a shutdown only
// cancels after the listener has stopped.
func (app *instance) reconcile(ctx context.Context) {
	if app.services.oidcService != nil {
		app.services.oidcService.ReconcileConsents(ctx)
	}
}

// shutdown stops the routines of the instance and waits for them to finish
func (app *instance) shutdown() {
	app.cancel(nil)
	app.stopRoutines()
	app.ding.Wait()
}

func (app *instance) setup() error {
	// provide basic utilities to container
	type utilityProvider struct {
		dig.Out

		Log     *logger.Logger
		Config  *model.Config
		Runtime *model.RuntimeConfig
		Ding    *ding.Ding
		Ctx     context.Context
		Queries repository.Store

		AuthCaches *service.AuthCaches
		OIDCCaches *service.OIDCCaches
	}

	err := app.dig.Provide(func() utilityProvider {
		return utilityProvider{
			Log:     app.log,
			Config:  &app.config,
			Runtime: &app.runtime,
			Ding:    app.ding,
			Ctx:     app.ctx,
			Queries: app.queries,

			AuthCaches: app.authCaches,
			OIDCCaches: app.oidcCaches,
		}
	})

	if err != nil {
		return fmt.Errorf("failed to provide utilities to container: %w", err)
	}

	// services
	err = app.setupServices()

	if err != nil {
		return fmt.Errorf("failed to initialize services: %w", err)
	}

	// configured providers
	configuredProviders := make([]model.Provider, 0)

	for id, provider := range app.runtime.OAuthProviders {
		configuredProviders = append(configuredProviders, model.Provider{
			Name:  provider.Name,
			ID:    id,
			OAuth: true,
		})
	}

	sort.Slice(configuredProviders, func(i, j int) bool {
		return configuredProviders[i].Name < configuredProviders[j].Name
	})

	if app.services.authService.LocalAuthConfigured() {
		configuredProviders = append(configuredProviders, model.Provider{
			Name:  "Local",
			ID:    "local",
			OAuth: false,
		})
	}

	if app.services.authService.LDAPAuthConfigured() {
		configuredProviders = append(configuredProviders, model.Provider{
			Name:  "LDAP",
			ID:    "ldap",
			OAuth: false,
		})
	}

	if len(configuredProviders) == 0 {
		return errors.New("no authentication providers configured")
	}

	for _, provider := range configuredProviders {
		app.log.App.Debug().Str("provider", provider.Name).Msg("Configured authentication provider")
	}

	app.runtime.ConfiguredProviders = configuredProviders

	// setup router
	err = app.setupRouter()

	if err != nil {
		return fmt.Errorf("failed to setup routes: %w", err)
	}

	return nil
}

// setupRuntime fills the runtime config with the values derived from the config
func (app *instance) setupRuntime() error {
	// get app url
	appURL, err := utils.SafeParseAppURL(app.config.AppURL)

	if err != nil {
		return fmt.Errorf("failed to parse app url: %w", err)
	}

	app.runtime.AppURL = appURL

	// validate session config
	if app.config.Auth.SessionMaxLifetime != 0 && app.config.Auth.SessionMaxLifetime < app.config.Auth.SessionExpiry {
		return errors.New("session max lifetime cannot be less than session expiry")
	}

	// parse users
	users, err := utils.GetUsers(app.config.Auth.Users, app.config.Auth.UsersFile, app.config.Auth.UserAttributes)

	if err != nil {
		return fmt.Errorf("failed to load users: %w", err)
	}

	if users != nil {
		app.runtime.LocalUsers = *users
	} else {
		app.log.App.Debug().Msg("No local users found, local authentication will not be available")
		app.runtime.LocalUsers = []model.LocalUser{}
	}

	// load oauth whitelist
	oauthWhitelist, err := utils.GetStringList(app.config.OAuth.Whitelist, app.config.OAuth.WhitelistFile)

	if err != nil {
		return fmt.Errorf("failed to load oauth whitelist: %w", err)
	}

	app.runtime.OAuthWhitelist = oauthWhitelist

	// setup oauth providers
	app.runtime.OAuthProviders = app.config.OAuth.Providers

	for id, provider := range app.runtime.OAuthProviders {
		if slices.Contains(model.ReservedProviderNames, id) {
			return fmt.Errorf("provider id %s is reserved and cannot be used", id)
		}

		providerWhitelist, err := utils.GetStringList(provider.Whitelist, provider.WhitelistFile)
		if err != nil {
			return fmt.Errorf("failed to load oauth whitelist for provider %s: %w", id, err)
		}

		provider.Whitelist = providerWhitelist

		secret := utils.GetSecret(provider.ClientSecret, provider.ClientSecretFile)
		provider.ClientSecret = secret
		provider.ClientSecretFile = ""

		if provider.Name == "" {
			if name, ok := model.OverrideProviders[id]; ok {
				provider.Name = name
			} else {
				provider.Name = utils.Capitalize(id)
			}
		}

		if provider.RedirectURL == "" {
			provider.RedirectURL = app.runtime.AppURL + "/api/oauth/callback/" + id
		}

		app.runtime.OAuthProviders[id] = provider
	}

	cookieDomain, err := utils.GetCookieDomain(app.runtime.AppURL, app.config.Auth.SubdomainsEnabled)

	if err != nil {
		return fmt.Errorf("failed to get cookie domain: %w", err)
	}

	app.runtime.CookieDomain = cookieDomain

	// cookie names
	u, err := url.Parse(app.runtime.AppURL)

	if err != nil {
		return fmt.Errorf("failed to parse app url: %w", err)
	}

	app.runtime.UUID = utils.GenerateUUID(u.Hostname())

	cookieId := strings.Split(app.runtime.UUID, "-")[0] // first 8 characters of the uuid should be good enough

	app.runtime.SessionCookieName = fmt.Sprintf("%s-%s", model.SessionCookieName, cookieId)
	app.runtime.OAuthSessionCookieName = fmt.Sprintf("%s-%s", model.OAuthSessionCookieName, cookieId)

	return nil
}
