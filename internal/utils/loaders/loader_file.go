package loaders

import (
	"os"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/paerser/file"
	"github.com/tinyauthapp/paerser/flag"
)

type FileLoader struct{}

// ConfigFile returns the path of the configuration file given by the flag, or
// else by the environment variable, and whether one is given
func ConfigFile(args []string, element any) (string, bool, error) {
	flags, err := flag.Parse(args, element)

	if err != nil {
		return "", false, err
	}

	// I guess we are using traefik as the root name (we can't change it)
	configFileFlag := "traefik.configfile"
	envVar := "TINYAUTH_CONFIGFILE"

	if value, ok := flags[configFileFlag]; ok {
		return value, true, nil
	}

	if value := os.Getenv(envVar); value != "" {
		return value, true, nil
	}

	return "", false, nil
}

func (f *FileLoader) Load(args []string, cmd *cli.Command) (bool, error) {
	path, ok, err := ConfigFile(args, cmd.Configuration)

	if err != nil {
		return false, err
	}

	if !ok {
		return false, nil
	}

	err = file.Decode(path, cmd.Configuration)

	if err != nil {
		return false, err
	}

	return true, nil
}
