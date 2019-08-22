package network

import (
	"github.com/niclabs/tcrsa"
)

// A connection represents a way to communicate with the nodes.
type Connection interface {
	// SendKeyShares send a list of keys to all the connected nodes.
	// The connection is started automatically if has not been started before.
	// If it can't send the message to all the nodes, it returns an error.
	SendKeyShares(id string, keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error

	// AckKeyShares confirms that all the nodes had received their keys.
	// It uses the timeout defined on the connection configuration to wait for the responses.
	// If it does not receive all the responses until the timeout, it throws an error.
	AckKeyShares() error

	// AskForSigShares asks for the signature shares over a given hash with a specific Key. If it is not able to ask for them, it returns an error.
	// The connection is started automatically if has not been started before.
	AskForSigShares(id string, hash []byte) error

	// GetSigShares waits for the signatures the timeout set on the connection configuration.
	// Even if there is no error, you must check if the SigShares received are enough for your use case, because the method returns only the sigshares that arrived before the timeout (they could be zero).
	GetSigShares() (tcrsa.SigShareList, error)

	// AskForKeyDeletion asks the nodes to delete a key share.
	AskForKeyDeletion(id string) error

	// GetKeyDeletionAck receives the acks from the nodes for having deleted the keys. It returns an error on timeout and the number of acks received. The error should not be critical.
	// The connection is started automatically if not started before.
	GetKeyDeletionAck() (int, error)

	// Close finishes the operation of the connection. If it's already closed, it does nothing.
	Close() error
}
