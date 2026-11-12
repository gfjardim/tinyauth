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

	// every subtest gets its own file, so that each can run alone
	newConfigFile := func(t *testing.T) (string, []string) {
		t.Helper()
		configFile := filepath.Join(t.TempDir(), "config.yml")
		return configFile, []string{"--configfile=" + configFile}
	}

	writeConfig := func(t *testing.T, configFile string, contents string) {
		t.Helper()
		require.NoError(t, os.WriteFile(configFile, []byte(contents), 0600))
	}

	t.Run("loads the configuration over the defaults", func(t *testing.T) {
		configFile, args := newConfigFile(t)
		writeConfig(t, configFile, "apps:\n  foo:\n    config:\n      domain: foo.example.com\n")

		cfg, err := loadConfig(args, resources)
		require.NoError(t, err)

		assert.Equal(t, map[string]model.App{
			"foo": {Config: model.AppConfig{Domain: "foo.example.com"}},
		}, cfg.Apps)
		assert.Equal(t, model.NewDefaultConfiguration(model.DetectRuntimeEnv()).Server, cfg.Server)
	})

	t.Run("reads the file again on every call", func(t *testing.T) {
		configFile, args := newConfigFile(t)
		writeConfig(t, configFile, "apps:\n  foo:\n    config:\n      domain: foo.example.com\n")

		_, err := loadConfig(args, resources)
		require.NoError(t, err)

		writeConfig(t, configFile, "apps:\n  bar:\n    config:\n      domain: bar.example.com\n")

		cfg, err := loadConfig(args, resources)
		require.NoError(t, err)

		assert.Equal(t, map[string]model.App{
			"bar": {Config: model.AppConfig{Domain: "bar.example.com"}},
		}, cfg.Apps)
	})

	t.Run("returns an error for a malformed file", func(t *testing.T) {
		configFile, args := newConfigFile(t)
		writeConfig(t, configFile, "apps: [")

		_, err := loadConfig(args, resources)
		assert.Error(t, err)
	})

	t.Run("returns an error for a missing file", func(t *testing.T) {
		_, args := newConfigFile(t)

		_, err := loadConfig(args, resources)
		assert.Error(t, err)
	})
}
