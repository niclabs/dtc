package zmq

import (
	"bytes"
	"dtcmaster/network"
	"encoding/gob"
	"fmt"
	"github.com/niclabs/tcrsa"
	"github.com/pebbe/zmq4"
	"log"
	"net"
	"sync"
	"time"
)

// TchsmDomain is the default domain for ZMQ context.
const TchsmDomain = "tchsm"

// This error represents a timeout situation
var TimeoutError = fmt.Errorf("timeout")

// ZMQ Structure represents a connection to a set of Nodes via ZMQ
// Messaging Protocol.
type ZMQ struct {
	// config properties
	ip      net.IP        // IP of service
	port    uint16        // Port where server ROUTER socket runs on
	privKey string        // Private Key of node
	pubKey  string        // Public Key of node
	timeout time.Duration // Length of timeout in seconds
	// nodes
	nodes []*Node // List of connected nodes of type ZMQ
	// zmq context
	ctx          *zmq4.Context // ZMQ Context
	serverSocket *zmq4.Socket  // ROUTER socket which receives the responses from the nodes
	// message related structs
	channel         chan *Message       // The channel where all the responses from router are sent.
	pendingMessages map[string]*Message // A map with requests without response. To know what messages I'm expecting.
	mutex           sync.Mutex          // A mutex to operate the pendingMessages map.
	currentMessage  network.MessageType // A label which indicates the operation the connection is doing right now. It avoids inconsistent states (i.e. ask for a type of resource and then collect another one).
}

// New returns a new ZMQ connection based in the configuration provided.
func New(config *Config) (conn *ZMQ, err error) {
	context, err := zmq4.NewContext()
	if err != nil {
		return
	}
	conn = &ZMQ{
		ip:              net.ParseIP(config.IP),
		port:            config.Port,
		privKey:         config.PrivateKey,
		pubKey:          config.PublicKey,
		timeout:         time.Duration(config.Timeout) * time.Second,
		ctx:             context,
		channel:         make(chan *Message, 8), // TODO: change this
		pendingMessages: make(map[string]*Message),
	}
	nodes := make([]*Node, len(config.Nodes))
	for i := 0; i < len(config.Nodes); i++ {
		nodes[i] = &Node{
			ip:     net.ParseIP(config.Nodes[i].IP),
			port:   config.Nodes[i].Port,
			pubKey: config.Nodes[i].PublicKey,
			conn:   conn,
		}
	}
	conn.nodes = nodes
	return
}

// Open opens the connection and initializes the binding with the nodes.
// It also starts polling responses from the ROUTER socket on the server.
func (conn *ZMQ) Open() (err error) {
	err = zmq4.AuthStart()
	if err != nil {
		return
	}
	// Create socket
	socket, err := conn.ctx.NewSocket(zmq4.ROUTER)
	if err != nil {
		return
	}

	// wait forever for messages
	if err = socket.SetRcvtimeo(-1); err != nil {
		return
	}

	conn.serverSocket = socket

	// Add all IPs in domain as allowed
	err = conn.serverSocket.ServerAuthCurve(TchsmDomain, conn.privKey)
	if err != nil {
		return
	}

	// Bind
	err = conn.serverSocket.Bind(conn.GetConnString())
	if err != nil {
		return
	}

	// Add peers to auth curve allowed and try to connect to them
	for _, node := range conn.nodes {
		zmq4.AuthCurveAdd(TchsmDomain, node.pubKey)
		node.connect()
	}

	// Start message polling
	go func() {
		for {
			rawMsg, err := conn.serverSocket.RecvMessageBytes(0)
			if err != nil {
				log.Printf("cannot receive messages: %s", err)
			}
			msg, err := MessageFromBytes(rawMsg)
			if err != nil {
				log.Printf("cannot parse messages: %s", err)
			}
			conn.channel <- msg
		}
	}()

	return
}

// GetNodes returns a list with the nodes.
// TODO: ¿Do we need this function?
func (conn *ZMQ) GetNodes() (nodes []network.Node) {
	nodes = make([]network.Node, 0)
	for _, node := range conn.nodes {
		nodes = append(nodes, node)
	}
	return
}

// GetNodeByID returns a node with the same ID than the provided argument, or nil if it doesn't exist.
func (conn *ZMQ) GetNodeByID(id string) *Node {
	for _, node := range conn.nodes {
		if node.GetID() == id {
			return node
		}
	}
	return nil
}

// GetActiveNodes returns a list with the active nodes.
// TODO: ¿Do we need this function?
func (conn *ZMQ) GetActiveNodes() (nodes []network.Node) {
	nodes = make([]network.Node, 0)
	for _, node := range conn.nodes {
		if node.Err == nil {
			nodes = append(nodes, node)
		}
	}
	return
}

// SendKeyShares send a list of keys to all the connected nodes.
// It requieres that the number of connected nodes is equal to the number of connected shares.
// If that is not the case, it returns an error.
func (conn *ZMQ) SendKeyShares(keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if len(keys) != len(conn.nodes) {
		return fmt.Errorf("number of keys is not equal to number of nodes")
	}
	if conn.currentMessage != network.None {
		return fmt.Errorf("cannot send key shares in a currentMessage state different to None")
	}
	for i, node := range conn.nodes {
		message, err := node.sendKeyShare(keys[i], meta)
		if err != nil {
			return fmt.Errorf("error with node %d: %s", i, err)
		}
		conn.pendingMessages[message.ID] = message
	}
	conn.currentMessage = network.SendKeyShare
	return nil
}

// AckKeyShares confirms that all the nodes had received their keys.
// It uses the timeout defined on the connection configuration to wait for the responses.
// If it doesn't receive enough responses until the timeout, it throws an error.
func (conn *ZMQ) AckKeyShares() error {
	conn.mutex.Lock()
	defer func() {
		conn.pendingMessages = make(map[string]*Message)
		conn.currentMessage = network.None
		conn.mutex.Unlock()
	}()
	if conn.currentMessage != network.SendKeyShare {
		return fmt.Errorf("cannot ack key shares in a currentMessage state different to sendKeyShare")
	}
	ackd := 0
	timer := time.After(conn.timeout)
	for {
		select {
		case msg := <-conn.channel:
			if pending, exists := conn.pendingMessages[msg.ID]; exists && msg.Ok(pending) {
				delete(conn.pendingMessages, msg.ID)
				ackd++
				if ackd == len(conn.nodes) {
					return nil
				}
			} else if !exists {
				log.Printf("unexpected message: %v", msg)
			} else if msg.Error != NoError {
				return fmt.Errorf("error with message: %s", pending.Error.Error())
			} else {
				return fmt.Errorf("message mismatch: request: [%v], response: [%v]", pending, msg)
			}
		case <-timer:
			return TimeoutError
		}
	}
}

// AskForSigShares asks for the signature shares over a given hash.
func (conn *ZMQ) AskForSigShares(hash []byte) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if conn.currentMessage != network.None {
		return fmt.Errorf("cannot ask for sig shares in a currentMessage state different to None")
	}
	for _, node := range conn.nodes {
		message, err := node.AskForSigShare(hash)
		if err != nil {
			return fmt.Errorf("error asking sigshare with node %s: %s", node.GetID(), err)
		}
		conn.pendingMessages[message.ID] = message
	}
	conn.currentMessage = network.AskForSigShare
	return nil
}

// GetSigShares waits for the signatures the timeout set on the connection configuration.
// It returns only the sigshares that arrived before the timeout (they could be zero).
func (conn *ZMQ) GetSigShares() (tcrsa.SigShareList, error) {
	conn.mutex.Lock()
	defer func() {
		conn.pendingMessages = make(map[string]*Message)
		conn.currentMessage = network.None
		conn.mutex.Unlock()
	}()
	if conn.currentMessage != network.AskForSigShare {
		return nil, fmt.Errorf("cannot get sig shares in a currentMessage state different to askForSigShare")
	}
	sigShares := make(tcrsa.SigShareList, 0)
	timer := time.After(conn.timeout)

L:
	for {
		select {
		case msg := <-conn.channel:
			if pending, exists := conn.pendingMessages[msg.ID]; exists && msg.Ok(pending) {
				sigShare := &tcrsa.SigShare{}
				delete(conn.pendingMessages, msg.ID)
				if err := gob.NewDecoder(bytes.NewBuffer(msg.Data[0])).Decode(sigShare); err != nil {
					log.Printf("corrupt key: %v", msg)
					// Ask for it again?
					node := conn.GetNodeByID(msg.NodeID)
					newRequest, err := node.AskForSigShare(pending.Data[0])
					if err != nil {
						log.Printf("error asking sigshare with node %s: %s", node.GetID(), err)
					}
					// save it in pending
					conn.pendingMessages[newRequest.ID] = newRequest
				} else {
					sigShares = append(sigShares, sigShare)
					if len(sigShares) == len(conn.nodes) {
						break L
					}
				}
			} else if !exists {
				log.Printf("unexpected message: %v", msg)
			} else if msg.Error != NoError {
				return nil, fmt.Errorf("error with message: %s", pending.Error.Error())
			} else {
				return nil, fmt.Errorf("message mismatch: request: [%v], response: [%v]", pending, msg)
			}
		case <-timer:
			break L
		}
	}
	return sigShares, nil
}

// GetConnString returns a formatted connection string.
func (conn *ZMQ) GetConnString() string {
	return fmt.Sprintf("tcp://%s:%d", conn.ip, conn.port)
}

// Close finishes the operation of the connection.
func (conn *ZMQ) Close() error {
	err := conn.serverSocket.Disconnect(conn.GetConnString())
	if err != nil {
		return err
	}
	// Try to connect to peers
	for _, node := range conn.nodes {
		err = node.Disconnect()
		if err != nil {
			return err
		}
	}
	zmq4.AuthStop()
	return nil
}
