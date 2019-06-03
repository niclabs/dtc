package zmq

import (
	"bytes"
	"dtcmaster/network"
	"dtcmaster/utils"
	"encoding/gob"
	"fmt"
	"github.com/niclabs/tcrsa"
	"github.com/pebbe/zmq4"
	"log"
	"net"
	"os"
)

type NodeState int

// A node represents a remote machine
type Node struct {
	ip              net.IP
	id              string
	port            uint16
	pubKey          string
	socket          *zmq4.Socket
	ctx             *zmq4.Context
	conn            *ZMQ
	Err             error
}

func (node *Node) connect() {
	// Create and name socket
	pubSock, err := node.conn.ctx.NewSocket(zmq4.PUSH)
	if err != nil {
		node.Err = err
		return
	}

	// config timeout as conn timeout
	if err = pubSock.SetSndtimeo(node.conn.timeout); err != nil {
		return
	}

	// Config CURVE
	nodePublic, err := zmq4.AuthCurvePublic(node.pubKey)
	if err != nil {
		node.Err = err
		return
	}
	node.socket = pubSock
	if err = node.socket.ClientAuthCurve(nodePublic, node.conn.pubKey, node.conn.privKey); err != nil {
		node.Err = err
		return
	}
	// connect
	_, _ = fmt.Fprintf(os.Stderr, "connecting to %s\n", node.GetConnString())
	if err = node.socket.Connect(node.GetConnString()); err != nil {
		node.Err = err
		return
	}
	// Put an ID to the node
	id, err := utils.GetRandomHexString(16)
	if err != nil {
		node.Err = err
		return
	}
	node.id = id
}

func (node *Node) GetID() string {
	return node.id
}

func (node *Node) sendKeyShare(key *tcrsa.KeyShare, meta *tcrsa.KeyMeta) (*Message, error) {
	var keyBuffer bytes.Buffer
	keyEncoder := gob.NewEncoder(&keyBuffer)
	var metaBuffer bytes.Buffer
	metaEncoder := gob.NewEncoder(&metaBuffer)
	if err := keyEncoder.Encode(key); err != nil {
		return nil, err
	}
	if err := metaEncoder.Encode(meta); err != nil {
		return nil, err
	}
	keyBinary := keyBuffer.Bytes()
	metaBinary := metaBuffer.Bytes()
	message, err := NewMessage(network.SendKeyShare, node.GetID(), keyBinary, metaBinary)
	if err != nil {
		return nil, err
	}
	log.Printf("Sending message to %s", node.GetConnString());
	if _, err = node.socket.SendMessage(message.GetBytesLists()); err != nil {
		return nil, err
	}
	return message, nil
}


func (node *Node) AskForSigShare(doc []byte) (message *Message, err error) {
	message, err = NewMessage(network.AskForSigShare, node.GetID(), doc)
	if err != nil {
		return nil, err
	}
	if _, err := node.socket.SendMessage(message.GetBytesLists()); err != nil {
		return nil, err
	}
	return message, nil
}


func (node *Node) GetError() error {
	return node.Err
}

func (node *Node) IsConnected() bool {
	return node.Err == nil
}

func (node *Node) GetConnString() string {
	return fmt.Sprintf("tcp://%s:%d", node.ip, node.port)
}

func (node *Node) Disconnect() error {
	return node.socket.Disconnect(node.GetConnString())
}
