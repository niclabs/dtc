package zmq

import (
	"github.com/spf13/viper"
)

type Config struct {
	Host       string
	Port       uint16
	PublicKey  string
	PrivateKey string
	Nodes      []*NodeConfig
	Timeout    uint16
}

type NodeConfig struct {
	PublicKey string
	Host      string
	Port      uint16
}

func GetConfig() (*Config, error) {
	var conf Config
	err := viper.UnmarshalKey("zmq", &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
