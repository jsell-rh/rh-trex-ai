package environments

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/spf13/pflag"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/client/apiclient"
	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/config"
	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/errors"
	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/registry"
)

var (
	globalEnv  *Env
	globalOnce sync.Once
	envImpls   map[string]EnvironmentImpl
)

func NewEnvironment(impls map[string]EnvironmentImpl) *Env {
	globalOnce.Do(func() {
		globalEnv = &Env{}
		globalEnv.Config = config.NewApplicationConfig()
		globalEnv.Name = GetEnvironmentStrFromEnv()
		envImpls = impls
	})
	return globalEnv
}

func (e *Env) SetEnvironmentImpls(impls map[string]EnvironmentImpl) {
	envImpls = impls
}

func Environment() *Env {
	if globalEnv == nil {
		panic("environments.Environment() called before NewEnvironment() — ensure your cmd/<service>/environments package is imported in main.go for its init() side-effect")
	}
	return globalEnv
}

func GetEnvironmentStrFromEnv() string {
	envStr, specified := os.LookupEnv(EnvironmentStringKey)
	if !specified || envStr == "" {
		envStr = EnvironmentDefault
	}
	return envStr
}

func (e *Env) AddFlags(flags *pflag.FlagSet) error {
	e.Config.AddFlags(flags)
	return SetConfigDefaults(flags, envImpls[e.Name].Flags())
}

func (e *Env) Initialize() error {
	envImpl, found := envImpls[e.Name]
	if !found {
		return fmt.Errorf("unknown runtime environment: %s", e.Name)
	}

	if err := envImpl.OverrideConfig(e.Config); err != nil {
		return fmt.Errorf("failed to configure ApplicationConfig: %w", err)
	}

	// Apply --log-level and --log-format before anything else logs.
	if err := e.Config.Logging.Install(); err != nil {
		return fmt.Errorf("failed to configure logging: %w", err)
	}
	slog.Info("Initializing environment", "environment", e.Name)

	messages := globalEnv.Config.ReadFiles()
	if len(messages) != 0 {
		return fmt.Errorf("unable to read configuration files:\n%s", strings.Join(messages, "\n"))
	}

	// Validate after ReadFiles so file-derived values (for example TLS
	// certificate paths filled in from the environment) are already in place.
	if messages := globalEnv.Config.Validate(); len(messages) != 0 {
		return fmt.Errorf("invalid configuration:\n%s", strings.Join(messages, "\n"))
	}

	if err := envImpl.OverrideDatabase(&e.Database); err != nil {
		return fmt.Errorf("failed to configure Database: %w", err)
	}

	err := e.LoadClients()
	if err != nil {
		return err
	}
	if err := envImpl.OverrideClients(&e.Clients); err != nil {
		return fmt.Errorf("failed to configure Clients: %w", err)
	}

	e.LoadServices()
	if err := envImpl.OverrideServices(&e.Services); err != nil {
		return fmt.Errorf("failed to configure Services: %w", err)
	}

	seedErr := e.Seed()
	if seedErr != nil {
		return seedErr
	}

	if err := envImpl.OverrideHandlers(&e.Handlers); err != nil {
		return fmt.Errorf("failed to configure Handlers: %w", err)
	}

	return nil
}

func (e *Env) Seed() *errors.ServiceError {
	return nil
}

func (e *Env) LoadServices() {
	e.Services.InitRegistry()

	registry.LoadDiscoveredServices(&e.Services, e)
}

func (e *Env) LoadClients() error {
	var err error

	apiClientConfig := apiclient.Config{
		BaseURL:      e.Config.APIClient.BaseURL,
		ClientID:     e.Config.APIClient.ClientID,
		ClientSecret: e.Config.APIClient.ClientSecret,
		SelfToken:    e.Config.APIClient.SelfToken,
		TokenURL:     e.Config.APIClient.TokenURL,
		Debug:        e.Config.APIClient.Debug,
	}

	if e.Config.APIClient.EnableMock {
		slog.Info("Using mock authz client")
		e.Clients.APIClient, err = apiclient.NewClientMock(apiClientConfig)
	} else {
		e.Clients.APIClient, err = apiclient.NewClient(apiClientConfig)
	}
	if err != nil {
		return fmt.Errorf("unable to create API authz client: %w", err)
	}

	return nil
}

func (e *Env) Teardown() {
	if e.Database.SessionFactory != nil {
		if err := e.Database.SessionFactory.Close(); err != nil {
			slog.Error("Error closing database session factory", "error", err)
		}
	}
	e.Clients.APIClient.Close()
}

func SetConfigDefaults(flags *pflag.FlagSet, defaults map[string]string) error {
	for name, value := range defaults {
		if err := flags.Set(name, value); err != nil {
			return fmt.Errorf("error setting flag %s: %w", name, err)
		}
	}
	return nil
}
