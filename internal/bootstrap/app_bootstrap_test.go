package bootstrap

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinyauthapp/tinyauth/internal/test"
)

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
