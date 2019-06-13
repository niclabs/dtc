package network

import (
	"github.com/niclabs/tcrsa"
)

type Connection interface {
	Open() error
	GetNodes() []Node
	GetActiveNodes() []Node
	SendKeyShares(id string, keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error
	AckKeyShares() error
	AskForSigShares(id string, hash []byte) error
	GetSigShares() (tcrsa.SigShareList, error)
	Close() error
}
