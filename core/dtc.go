package core

import (
	"dtcmaster/network"
	"fmt"
	"github.com/niclabs/tcrsa"
	"os"
)

type DTC struct {
	InstanceID   string
	ConnectionID int
	Timeout      uint16
	Messenger    network.Connection
	KeyMeta      tcrsa.KeyMeta

}

func getConnectionID() int {
	return os.Getpid()
}

func NewDTC(config DTCConfig) *DTC {
	return &DTC{
		InstanceID: config.InstanceID,
		ConnectionID: getConnectionID(),
		Timeout: config.Timeout,
	}
}


func (dtc *DTC) GenerateKeyShares(keyID string, bitSize int, k, l uint16) error {
	if l < 1 {
		return fmt.Errorf("node number must be greater than one")
	}
	keyShares, keyMeta, err := tcrsa.NewKey(bitSize, k, l, nil)
	if err != nil {
		return err
	}
}