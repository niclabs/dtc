package main

import "C"
import (
	"dtc/network"
	"github.com/niclabs/tcrsa"
	"log"
)

// DTC represents the Distributed Threshold Criptography library. It manages on its own the nodes, and exposes a simple API to use it.
type DTC struct {
	Connection network.Connection // The messenger DTC uses to communicate with the nodes.
	Threshold  uint16             // The threshold defined in the model.
	Nodes      uint16             // The total number of nodes used.
}

// Creates a new and ready DTC struct. It connects automatically to its nodes.
func NewDTC(config DTCConfig) (*DTC, error) {
	connection, err := NewConnection(config.MessagingType)
	if err != nil {
		return nil, err
	}
	dtc := &DTC{
		Threshold:  config.Threshold,
		Nodes:      config.NodesNumber,
		Connection: connection,
	}

	if err = connection.Open(); err != nil {
		return nil, err
	}
	return dtc, nil
}

// Creates a new key and saves its shares distributed among all the nodes.
func (dtc *DTC) CreateNewKey(keyID string, bitSize int, args *tcrsa.KeyMetaArgs) (*tcrsa.KeyMeta, error) {
	log.Printf("Creating new key with bitsize=%d, threshold=%d and nodes=%d", bitSize, dtc.Threshold, dtc.Nodes)
	keyShares, keyMeta, err := tcrsa.NewKey(bitSize, dtc.Threshold, dtc.Nodes, args)
	if err != nil {
		return nil, err
	}
	log.Printf("Sending key shares with keyid=%s", keyID)
	if err := dtc.Connection.SendKeyShares(keyID, keyShares, keyMeta); err != nil {
		return nil, err
	}
	log.Printf("Acking key shares related to keyid=%s", keyID)
	if err := dtc.Connection.AckKeyShares(); err != nil {
		return nil, err
	}
	return keyMeta, nil
}

// Signs with a key name a byte hash, sending it to all the keyshare holders.
func (dtc *DTC) SignData(keyName string, meta *tcrsa.KeyMeta, data []byte) ([]byte, error) {
	if err := dtc.Connection.AskForSigShares(keyName, data); err != nil {
		return nil, err
	}
	// We get the sig shares
	sigShareList, err := dtc.Connection.GetSigShares()
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
