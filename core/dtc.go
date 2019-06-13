package core

import (
	"dtcmaster/network"
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

func getConnectionID() int {
	return os.Getpid()
}

func NewDTC(config DTCConfig) *DTC {
	return &DTC{
		InstanceID:   config.InstanceID,
		ConnectionID: getConnectionID(),
		Timeout:      config.Timeout,
		Threshold:    config.Threshold,
		Nodes:        config.NodesNumber,
	}
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
