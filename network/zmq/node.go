package zmq

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/niclabs/tcrsa"
	"github.com/pebbe/zmq4"
	"net"
)

const (
	SendKeyShare byte = iota
	GetSigShare
	InvalidMessage // Keep this at the end
)


type Node struct {
	ip     net.IP
	port   uint16
	pubKey string
	socket *zmq4.Socket
	ctx    *zmq4.Context
	conn   *ZMQ
	Err    error
}

func (node *Node) Sign(hash []byte, timeout int) (*tcrsa.SigShare, error) {
	panic("implement me")
}

func (node *Node) Connect() {
	// Create and name socket
	pubSock, err := node.conn.ctx.NewSocket(zmq4.PUSH)
	if err != nil {
		node.Err = err
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
	// Connect
	if err = node.socket.Connect(node.GetConnString()); err != nil {
		node.Err = err
		return
	}
}


func (node *Node) SendKeyShare(key *tcrsa.KeyShare, meta *tcrsa.KeyMeta, timeout int) error {
	var keyBuffer bytes.Buffer
	keyEncoder := gob.NewEncoder(&keyBuffer)
	var metaBuffer bytes.Buffer
	metaEncoder := gob.NewEncoder(&metaBuffer)
	if err := keyEncoder.Encode(key); err != nil {
		return err
	}
	if err := metaEncoder.Encode(meta); err != nil {
		return err
	}
	flagBinary := []byte{SendKeyShare}
	keyBinary := keyBuffer.Bytes()
	metaBinary := metaBuffer.Bytes()
	completeMsg := [][]byte{flagBinary, keyBinary, metaBinary}
	if _, err := node.socket.SendMessage(completeMsg); err != nil {
		return err
	}
	respMsg, err := node.socket.RecvMessageBytes(0)
	if err != nil {
		return err
	}
	if len(respMsg) != 2 || len(respMsg[0]) != 1 || respMsg[0][0] != SendKeyShare {
		err = fmt.Errorf("wrong response")
		return err
	}
	if string(respMsg[1]) != "ok" {
		return fmt.Errorf("error sending key")
	}
	return nil
}

func (node *Node) GetSigShare(doc []byte, timeout int) (sigShare *tcrsa.SigShare, err error) {
	flagBinary := []byte{GetSigShare}
	completeMsg := [][]byte{flagBinary, doc}
	if _, err := node.socket.SendMessage(completeMsg); err != nil {
		return nil, err
	}
	respMsg, err := node.socket.RecvMessageBytes(0)
	if err != nil {
		return
	}
	if len(respMsg) != 2 || len(respMsg[0]) != 1 || respMsg[0][0] != GetSigShare {
		err = fmt.Errorf("wrong response")
		return
	}
	respBuffer := bytes.NewBuffer(respMsg[1])
	sigDecoder := gob.NewDecoder(respBuffer)
	if err = sigDecoder.Decode(&sigShare); err != nil {
		return
	}
	return
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