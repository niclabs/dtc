package sqlite3

import "github.com/spf13/viper"

type Config struct {
	Path string
}

func GetConfig() (*Config, error) {
	var conf Config
	err := viper.UnmarshalKey("sqlite3", &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}