package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/loaders"
)

func TestLoadConfig(t *testing.T) {
	resources := []cli.ResourceLoader{
		&loaders.FileLoader{},
		&loaders.FlagLoader{},
		&loaders.EnvLoader{},
	}

	configFile := filepath.Join(t.TempDir(), "config.yml")
	args := []string{"--configfile=" + configFile}

	writeConfig := func(t *testing.T, contents string) {
		t.Helper()
		require.NoError(t, os.WriteFile(configFile, []byte(contents), 0600))
	}

	t.Run("loads the configuration over the defaults", func(t *testing.T) {
		writeConfig(t, "apps:\n  foo:\n    config:\n      domain: foo.example.com\n")

		cfg, err := loadConfig(args, resources)
		require.NoError(t, err)

		assert.Equal(t, map[string]model.App{
			"foo": {Config: model.AppConfig{Domain: "foo.example.com"}},
		}, cfg.Apps)
		assert.Equal(t, model.NewDefaultConfiguration(model.DetectRuntimeEnv()).Server, cfg.Server)
	})

	t.Run("reads the file again on every call", func(t *testing.T) {
		writeConfig(t, "apps:\n  bar:\n    config:\n      domain: bar.example.com\n")

		cfg, err := loadConfig(args, resources)
		require.NoError(t, err)

		assert.Equal(t, map[string]model.App{
			"bar": {Config: model.AppConfig{Domain: "bar.example.com"}},
		}, cfg.Apps)
	})

	t.Run("returns an error for a malformed file", func(t *testing.T) {
		writeConfig(t, "apps: [")

		_, err := loadConfig(args, resources)
		assert.Error(t, err)
	})

	t.Run("returns an error for a missing file", func(t *testing.T) {
		require.NoError(t, os.Remove(configFile))

		_, err := loadConfig(args, resources)
		assert.Error(t, err)
	})
}
