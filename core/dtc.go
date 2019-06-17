package core

import (
	"dtc/network"
	"dtc/network/zmq"
	"fmt"
	"github.com/niclabs/tcrsa"
	"os"
)

type DTC struct {
	InstanceID   string
	ConnectionID int
	Timeout      uint16
	Messenger    network.Connection
	Threshold    uint16
	Nodes        uint16
}

func NewConnection(dbType string) (conn network.Connection, err error) {
	switch dbType {
	case "zmq":
		zmqConfig, err1 := zmq.GetConfig()
		if err1 != nil {
			err = err1
			return
		}
		conn, err1 = zmq.New(zmqConfig)
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

func getConnectionID() int {
	return os.Getpid()
}

func NewDTC(config DTCConfig) (*DTC, error) {
	connection, err := NewConnection(config.MessagingType)
	if err != nil {
		return nil, err
	}
	return &DTC{
		InstanceID:   config.InstanceID,
		ConnectionID: getConnectionID(),
		Timeout:      config.Timeout,
		Threshold:    config.Threshold,
		Nodes:        config.NodesNumber,
		Messenger:    connection,
	}, nil
}

func (dtc *DTC) CreateNewKey(keyID string, bitSize int, args *tcrsa.KeyMetaArgs) (*tcrsa.KeyMeta, error) {
	keyShares, keyMeta, err := tcrsa.NewKey(bitSize, dtc.Threshold, dtc.Nodes, args)
	if err != nil {
		return nil, err
	}
	if err := dtc.Messenger.SendKeyShares(keyID, keyShares, keyMeta); err != nil {
		return nil, err
	}
	return keyMeta, nil
}

func (dtc *DTC) SignData(keyName string, meta *tcrsa.KeyMeta, data []byte) ([]byte, error) {
	if err := dtc.Messenger.AskForSigShares(keyName, data); err != nil {
		return nil, err
	}
	// We get the sig shares
	sigShareList, err := dtc.Messenger.GetSigShares();
	if err != nil {
		return nil, err
	}

	// We verify them
	for _, sigShare := range sigShareList {
		if err := sigShare.Verify(data, meta); err != nil {
			return nil, err
		}
	}
	// Finally We merge and return them
	return sigShareList.Join(data, meta)
}
