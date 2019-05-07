package messaging

import (
	"dtcmaster/messaging/zmq"
	"fmt"
)

type Messenger interface{
	OpenConnection() error
	SendToNodes(timeout int) error
	ReceiveFromNodes(timeout int) error
	CloseConnection() error
}

func NewMessenger(dbType string) (Messenger, error) {
	switch dbType {
	case "zmq":
		zmqConfig, err := zmq.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("zmq config not defined")
		}
		return zmq.New(zmqConfig)
	default:
		return nil, fmt.Errorf("storage option not found")
	}
	// TODO: More storage options.
}
