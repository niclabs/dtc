package core

import (
	"dtcmaster/messaging"
	"os"
)

type DTC struct {
	InstanceID string
	ConnectionID int
	Timeout uint16
	Messenger messaging.Messenger
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


func (dtc *DTC) GenerateKeyShares(keyID string, bitSize int, threshold, cantNodes uint16, )