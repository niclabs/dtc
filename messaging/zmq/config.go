package zmq

import (
	"fmt"
	"github.com/spf13/viper"
	"net"
)

type NetParams struct {
	IP net.IP
	Port uint16
}

type Config struct {
	Network    NetParams
	PublicKey  string
	PrivateKey string
	Nodes      []*NodeConfig
	Timeout    uint16
}

type NodeConfig struct {
	PublicKey string
	Network   NetParams
}


func (params *NetParams) String() string {
	return fmt.Sprintf("tcp://%s:%d", params.IP, params.Port)
}

func GetConfig() (*Config, error) {
	var conf Config
	err := viper.UnmarshalKey("zmq", &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
