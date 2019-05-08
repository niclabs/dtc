package network

import "github.com/niclabs/tcrsa"

type Node interface {
	Connect()
	SendKeyShare(key *tcrsa.KeyShare, meta *tcrsa.KeyMeta, timeout int) error
	Sign(hash []byte, timeout int) (*tcrsa.SigShare, error)
	GetError() error
	IsConnected() bool
	Disconnect() error
}