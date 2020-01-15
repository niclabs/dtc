package network

import (
	"github.com/niclabs/tcecdsa"
	"github.com/niclabs/tcrsa"
	"math/big"
)

// A connection represents a way to communicate with the nodes.
type Connection interface {
	RSAConnection
	// Open opens the connection and initializes the binding with the nodes.
	// If it is already open, it does nothing.
	Open() error
	// Close finishes the operation of the connection. If it's already closed, it does nothing.
	Close() error
}

type RSAConnection interface {
	// SendRSAKeyShares send a list of keys to all the connected nodes.
	// If it can't send the message to all the nodes, it returns an error
	SendRSAKeyShares(id string, keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error

	// AckRSAKeyShares confirms that all the nodes had received their keys.
	// It uses the timeout defined on the connection configuration to wait for the responses.
	// If it does not receive all the responses until the timeout, it throws an error.
	AckRSAKeyShares() error

	// AskForRSASigShares asks for the signature shares over a given hash with a specific Key. If it is not able to ask for them, it returns an error.
	AskForRSASigShares(id string, hash []byte) error

	// GetRSASigShares waits for the signatures the timeout set on the connection configuration, or until
	// k values are received. It returns an error if the number of sigshares is not k.
	GetRSASigShares(k int) (tcrsa.SigShareList, error)

	// AskForRSAKeyDeletion asks the nodes to delete a key share.
	AskForRSAKeyDeletion(id string) error

	// AckRSAKeyDeletion receives the acks from the nodes for having deleted the keys. It returns an error on timeout.
	//The error should not be critical.
	AckRSAKeyDeletion() error
}

type ECDSAConnection interface {

	// SendECDSAKeyShares send a list of keys to all the connected nodes.
	// If it can't send the message to all the nodes, it returns an error
	SendECDSAKeyShares(id string, keys []*tcecdsa.KeyShare, meta *tcecdsa.KeyMeta) error

	// GetECDSAKeyInitList receives all the KeyInitMessages from the nodes.
	GetECDSAKeyInitMessageList() (tcecdsa.KeyInitMessageList, error)

	// SendECDSAKeyInitMessageList sends the KeyInitMessageList to all the participant
	// nodes.
	SendECDSAKeyInitMessageList(tcecdsa.KeyInitMessageList) error

	// AckECDSAKeyInitReception confirms that all the nodes have received the
	// KeyInitMessageList.
	AckECDSAKeyInitReception() error

	// AskForECDSARound1MessageList asks all the nodes for its ECDSARound1MessageList,
	// sending them the message that will be signed.
	AskForECDSARound1MessageList(string, []byte) error

	// GetECDSARound1MessageList receives the Round1Message from K nodes.
	// the reception of this messages fix the nodes that will participate on
	// future rounds.
	GetECDSARound1MessageList() (tcecdsa.Round1MessageList, error)

	// AskForECDSARound2MessageList sends a list of K Round1Message to the
	// selected nodes.
	AskForECDSARound2MessageList(string, tcecdsa.Round1MessageList) error

	// GetECDSARound2MessageList returns a list of K Round2Message.
	GetECDSARound2MessageList() (tcecdsa.Round2MessageList, error)

	// AskForECDSARound3MessageList sends a list of K Round2Message to the
	// selected nodes.
	AskForECDSARound3MessageList(string, tcecdsa.Round2MessageList) error

	// GetECDSARound2MessageList returns a list of K Round3Message.
	GetECDSARound3MessageList() (tcecdsa.Round3MessageList, error)

	// AskForECDSASignature sends a list of K Round3Message to the
	// selected nodes.
	AskForECDSASignature(string, tcecdsa.Round3MessageList) error

	// GetECDSASignature returns r and s, parameters of the signature over
	// the message.
	GetECDSASignature() (*big.Int, *big.Int, error)


	// AskForECDSAKeyDeletion asks the nodes to delete a key share.
	AskForECDSAKeyDeletion(id string) error

	// AckECDSAKeyDeletion receives the acks from the nodes for having deleted the keys. It returns an error on timeout and the number of acks received. The error should not be critical.
	// The connection is started automatically if not started before.
	AckECDSAKeyDeletion() (int, error)
}
