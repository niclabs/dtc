package core

import (
	"fmt"
	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/dtc/")
	viper.AddConfigPath("$HOME/.dtc")
	viper.AddConfigPath("./")
	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("config file not found! %v", err))
	}
}

type Config struct {
	DTC      DTCConfig
	Criptoki CriptokiConfig
}

type DTCConfig struct {
	MessagingType string
	InstanceID    string
	Timeout       uint16
}

type CriptokiConfig struct {
	DatabaseType string
	NodesNumber  uint16
	Threshold    uint16
	Slots        []*SlotsConfig
}

type SlotsConfig struct {
	Label string
}

func GetConfig() (*Config, error) {
	var conf Config
	err := viper.Unmarshal(&conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
