package network

import (
	"github.com/niclabs/tcrsa"
)

// A connection represents a way to communicate with the nodes.
type Connection interface {

	// Open opens the connection and initializes the binding with the nodes.
	// It also starts polling responses from the ROUTER socket on the server.
	Open() error

	// SendKeyShares send a list of keys to all the connected nodes.
	// If it can't send the message to all the nodes, it returns an error
	SendKeyShares(id string, keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error

	// AckKeyShares confirms that all the nodes had received their keys.
	// It uses the timeout defined on the connection configuration to wait for the responses.
	// If it does not receive all the responses until the timeout, it throws an error.
	AckKeyShares() error

	// AskForSigShares asks for the signature shares over a given hash with a specific Key. If it is not able to ask for them, it returns an error.
	AskForSigShares(id string, hash []byte) error

	// GetSigShares waits for the signatures the timeout set on the connection configuration.
	// Even if there is no error, you must check if the SigShares received are enough for your use case, because the method returns only the sigshares that arrived before the timeout (they could be zero).
	GetSigShares() (tcrsa.SigShareList, error)

	// Close finishes the operation of the connection.
	Close() error
}
