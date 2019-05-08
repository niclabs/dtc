package core

import (
	"dtcmaster/network"
	"dtcmaster/network/zmq"
	"fmt"
)

func NewConnection(dbType string) (conn network.Connection, err error) {
	switch dbType {
	case "zmq":
		zmqConfig, err1 := zmq.GetConfig()
		if err1 != nil {
			err = err1
			return
		}
		conn, err1 := zmq.New(zmqConfig)
		if err1 != nil {
			err = err1
			return
		}
		return conn, nil
	default:
		err = fmt.Errorf("storage option not found")
		return
	}
	// TODO: More network options.
}
