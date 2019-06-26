package zmq

import (
	"fmt"
	"github.com/niclabs/dtcnode/message"
	"github.com/niclabs/tcrsa"
	"github.com/pebbe/zmq4"
	"log"
)

type NodeState int

// Node represents a remote machine connection. It has all the data required to connect to a node, and a pointer to use the respective Server struct.
type Node struct {
	host   string       // Host of remote node
	port   uint16       // Port of remote node SUB
	pubKey string       // Public key of remote node used in ZMQ CURVE Auth
	socket *zmq4.Socket // ZMQ4 Socket
	conn   *Server      // The server that manages this Node subroutine.
	Err    error        // The last error this node had.
}

func (node *Node) getID() string {
	return node.pubKey
}

func (node *Node) getConnString() string {
	return fmt.Sprintf("%s://%s:%d", TchsmProtocol, node.host, node.port)
}

func (node *Node) disconnect() error {
	return node.socket.Disconnect(node.getConnString())
}

func (node *Node) connect() error {
	// Create and name socket
	out, err := node.conn.ctx.NewSocket(zmq4.DEALER)
	if err != nil {
		node.Err = err
		return err
	}

	if err := out.SetIdentity(node.conn.pubKey); err != nil {
		node.Err = err
		return err
	}

	if err = out.ClientAuthCurve(node.pubKey, node.conn.pubKey, node.conn.privKey); err != nil {
		node.Err = err
		return err
	}
	// connect
	log.Printf("connecting to %s socket in %s", node.getID(), node.getConnString())
	if err = out.Connect(node.getConnString()); err != nil {
		node.Err = err
		return err
	}
	node.socket = out
	return nil
}

func (node *Node) sendKeyShare(id string, key *tcrsa.KeyShare, meta *tcrsa.KeyMeta) (*message.Message, error) {
	keyBinary, err := message.EncodeKeyShare(key)
	if err != nil {
		return nil, err
	}
	metaBinary, err := message.EncodeKeyMeta(meta)
	if err != nil {
		return nil, err
	}
	msg, err := message.NewMessage(message.SendKeyShare, node.getID(), []byte(id), keyBinary, metaBinary)
	if err != nil {
		return nil, err
	}
	_, err = node.socket.SendMessage(msg.GetBytesLists()...)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) askForSigShare(id string, doc []byte) (msg *message.Message, err error) {
	msg, err = message.NewMessage(message.AskForSigShare, node.getID(), []byte(id), doc)
	if err != nil {
		return nil, err
	}
	if _, err := node.socket.SendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}
