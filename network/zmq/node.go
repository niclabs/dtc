package zmq

import (
	"fmt"
	"github.com/niclabs/dtc/v3/config"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/pebbe/zmq4"
	"log"
	"net"
)

type NodeState int

// Node represents a remote machine connection. It has all the data required to connect to a node, and a pointer to use the respective Client struct.
type Node struct {
	host   *net.IPAddr  // Host of remote node
	port   uint16       // Port of remote node SUB
	pubKey string       // Public key of remote node used in ZMQ CURVE Auth
	socket *zmq4.Socket // ZMQ4 Socket
	client *Client      // The server that manages this Node subroutine.
	Err    error        // The last error this node had.
}

func newNode(client *Client, config *config.NodeConfig) (*Node, error) {
	var nodeIP *net.IPAddr
	nodeIP, err := net.ResolveIPAddr("ip", config.Host)
	if err != nil {
		return nil, err
	}
	return &Node{
		host:   nodeIP,
		port:   config.Port,
		pubKey: config.PublicKey,
		client: client,
	}, nil
}

func (node *Node) id() string {
	return node.client.ID
}

func (node *Node) getConnString() string {
	return fmt.Sprintf("%s://%s:%d", TchsmProtocol, node.host, node.port)
}

func (node *Node) disconnect() error {
	return node.socket.Disconnect(node.getConnString())
}

func (node *Node) connect() error {
	// Create and name socket
	s, err := node.client.ctx.NewSocket(zmq4.REQ)
	if err != nil {
		node.Err = err
		return err
	}
	node.socket = s
	if err := node.socket.SetIdentity(node.id()); err != nil {
		node.Err = err
		return err
	}

	if err = node.socket.ClientAuthCurve(node.pubKey, node.client.pubKey, node.client.privKey); err != nil {
		node.Err = err
		return err
	}

	// connect
	log.Printf("connecting to %s socket in %s", node.id(), node.getConnString())
	if err = node.socket.Connect(node.getConnString()); err != nil {
		node.Err = err
		return err
	}
	if err := node.socket.SetRcvtimeo(node.client.timeout); err != nil {
		node.Err = err
		return err
	}
	if err := node.socket.SetSndtimeo(node.client.timeout); err != nil {
		node.Err = err
		return err
	}
	return nil
}

func (node *Node) recvMessage() {
	rawMsg, err := node.socket.RecvMessageBytes(0)
	if err != nil {
		log.Printf("Error with new message: %v", err)
		return
	}
	msg, err := message.FromBytes(rawMsg)
	if err != nil {
		log.Printf("Cannot parse message: %s\n", err)
		return
	}
	node.client.channel <- msg
}
