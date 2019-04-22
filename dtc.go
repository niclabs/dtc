package main

import (
	"crypto/rsa"
	"net"
)

// Node represents the configuration of a participant of the dtc scheme.
type Node struct {
	IP net.IP // IP of the node
	SubPort uint16 // Subscription port
	DealPort uint16 // Dealer Port
	PubKey rsa.PublicKey // Public Key
}

// DTCConfig represents the configuration of an instance of the DTC Master Node
type DTCConfig struct {
	Timeout uint16 // Timeout for nodes
	NodeNum uint32 // Number of nodes to connect to. When the key is generated, all of them should be reachable.
	Nodes *Node // Each node configuration.
	Id string // ID of this instance
	PublicKey rsa.PublicKey // Public key of the master node
	PrivateKey rsa.PrivateKey // Private key of the master node
}

type DTC struct {
	Config *DTCConfig
}



func (dtc *DTC) LoadConfig() {

}

func (dtc *DTC) GenerateKeyShares() {

}

func (dtc *DTC) Sign() {

}

func (dtc *DTC) DeleteKeyShares() {

}

func (dtc *DTC) Init() {

}
