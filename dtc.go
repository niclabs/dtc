package main

import "C"
import (
	"fmt"
	"github.com/niclabs/dtc/v3/config"
	"github.com/niclabs/dtc/v3/network"
	"github.com/niclabs/tcrsa"
	"github.com/spf13/viper"
	"log"
	"sync"
)

func init() {
	viper.SetConfigName("config")
	viper.AddConfigPath("./")
	viper.AddConfigPath("$HOME/.dtc")
	viper.AddConfigPath("/etc/dtc/")
	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("config file problem %v", err))
	}
}

// DTC represents the Distributed Threshold Criptography library. It manages on its own the nodes, and exposes a simple API to use it.
type DTC struct {
	sync.Mutex
	Connection network.Connection // The messenger DTC uses to communicate with the nodes.
	Threshold  uint16             // The threshold defined in the model.
	Nodes      uint16             // The total number of nodes used.
}

// NewDTC creates a new and ready DTC struct. It connects automatically to its nodes.
func NewDTC(config config.DTCConfig) (*DTC, error) {
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

// CreateNewKeyRSA creates a new key and saves its shares distributed among all the nodes.
func (dtc *DTC) CreateNewKeyRSA(keyID string, bitSize int, args *tcrsa.KeyMetaArgs) (*tcrsa.KeyMeta, error) {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Creating new key with bitsize=%d, threshold=%d and nodes=%d", bitSize, dtc.Threshold, dtc.Nodes)
	keyShares, keyMeta, err := tcrsa.NewKey(bitSize, dtc.Threshold, dtc.Nodes, args)
	if err != nil {
		return nil, err
	}
	log.Printf("Sending key shares with keyid=%s", keyID)
	if err := dtc.Connection.SendRSAKeyShares(keyID, keyShares, keyMeta); err != nil {
		return nil, err
	}
	log.Printf("Acking key shares related to keyid=%s", keyID)
	if err := dtc.Connection.AckRSAKeyShares(); err != nil {
		return nil, err
	}
	return keyMeta, nil
}

// SignDataRSA with a key name a byte hash, sending it to all the keyshare holders.
func (dtc *DTC) SignDataRSA(keyName string, meta *tcrsa.KeyMeta, data []byte) ([]byte, error) {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Signing data with key of id=%s", keyName)
	if err := dtc.Connection.AskForRSASigShares(keyName, data); err != nil {
		return nil, err
	}
	// We get the sig shares
	sigShareList, err := dtc.Connection.GetRSASigShares(int(meta.K))
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

// DeleteKeyRSA an old key deleting the key shares from all the nodes.
func (dtc *DTC) DeleteKeyRSA(keyID string) error {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Deleting key shares with keyid=%s", keyID)
	if err := dtc.Connection.AskForRSAKeyDeletion(keyID); err != nil {
		return err
	}
	log.Printf("Acking key shares deletion related to keyid=%s", keyID)
	return dtc.Connection.AckRSAKeyDeletion()
}
