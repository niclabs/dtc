package network

import (
	"github.com/niclabs/tcrsa"
)

type Connection interface {
	Open() error
	GetNodes() []Node
	GetActiveNodes() []Node
	SendKeyShares(keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error
	AckKeyShares() error
	AskForSigShares(hash []byte) error
	GetSigShares() (tcrsa.SigShareList, error)
	Close() error
}
