package zmq

import (
	"dtcmaster/network"
	"dtcmaster/network/zmq/message"
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
const TchsmProtocol = "tcp"

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
	channel         chan *message.Message       // The channel where all the responses from router are sent.
	pendingMessages map[string]*message.Message // A map with requests without response. To know what messages I'm expecting.
	mutex           sync.Mutex                  // A mutex to operate the pendingMessages map.
	currentMessage  message.MessageType         // A label which indicates the operation the connection is doing right now. It avoids inconsistent states (i.e. ask for a type of resource and then collect another one).
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
		channel:         make(chan *message.Message, 8), // TODO: change this
		pendingMessages: make(map[string]*message.Message),
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
	if conn.nodes == nil {
		return fmt.Errorf("not initialized. Use 'New' to create a new struct")
	}
	err = zmq4.AuthStart()
	if err != nil {
		return
	}

	// Add IPs and public keys from clients
	zmq4.AuthAllow(TchsmDomain, conn.GetIPs()...)
	zmq4.AuthCurveAdd(TchsmDomain, conn.GetPubKeys()...)

	// Create in
	in, err := conn.ctx.NewSocket(zmq4.ROUTER)
	if err != nil {
		return
	}

	// wait forever for messages
	if err = in.SetRcvtimeo(-1); err != nil {
		return
	}

	// Add our private key
	err = in.ServerAuthCurve(TchsmDomain, conn.privKey)
	if err != nil {
		return
	}

	// Bind
	err = in.Bind(conn.GetConnString())
	if err != nil {
		return
	}
	conn.serverSocket = in

	// Now we connect to the clients
	for _, client := range conn.nodes {
		client.connect()
	}
	// Start message polling
	go func() {
		for {
			rawMsg, err := conn.serverSocket.RecvMessageBytes(0)
			if err != nil {
				continue
			}
			msg, err := message.FromBytes(rawMsg)
			if err != nil {
				log.Printf("cannot parse messages: %s\n", err)
				continue
			}
			conn.channel <- msg
		}
	}()

	return
}

func (conn *ZMQ) GetPubKeys() []string {
	pubKeys := make([]string, len(conn.nodes))
	for i, node := range conn.nodes {
		pubKeys[i] = node.pubKey
	}
	return pubKeys
}

func (conn *ZMQ) GetIPs() []string {
	ips := make([]string, len(conn.nodes))
	for i, node := range conn.nodes {
		ips[i] = node.ip.String()
	}
	return ips
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
func (conn *ZMQ) SendKeyShares(keyID string, keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if len(keys) != len(conn.nodes) {
		return fmt.Errorf("number of keys is not equal to number of nodes")
	}
	if conn.currentMessage != message.None {
		return fmt.Errorf("cannot send key shares in a currentMessage state different to None")
	}
	for i, node := range conn.nodes {
		message, err := node.sendKeyShare(keyID, keys[i], meta)
		if err != nil {
			return fmt.Errorf("error with node %d: %s", i, err)
		}
		conn.pendingMessages[message.ID] = message
	}
	conn.currentMessage = message.SendKeyShare
	return nil
}

// AckKeyShares confirms that all the nodes had received their keys.
// It uses the timeout defined on the connection configuration to wait for the responses.
// If it doesn't receive enough responses until the timeout, it throws an error.
func (conn *ZMQ) AckKeyShares() error {
	conn.mutex.Lock()
	defer func() {
		conn.pendingMessages = make(map[string]*message.Message)
		conn.currentMessage = message.None
		conn.mutex.Unlock()
	}()
	if conn.currentMessage != message.SendKeyShare {
		return fmt.Errorf("cannot ack key shares in a currentMessage state different to sendKeyShare")
	}
	acked := 0
	timer := time.After(conn.timeout)
	for {
		select {
		case msg := <-conn.channel:
			if pending, exists := conn.pendingMessages[msg.ID]; exists {
				if err := msg.Ok(pending, 0); err != nil {
					log.Printf("error with message: %v\n", msg)
				}
				delete(conn.pendingMessages, msg.ID)
				acked++
				if acked == len(conn.nodes) {
					return nil
				}
			} else {
				log.Printf("unexpected message: %v\n", msg)
			}
		case <-timer:
			return TimeoutError
		}
	}
}

// AskForSigShares asks for the signature shares over a given hash with a specific Key
func (conn *ZMQ) AskForSigShares(keyID string, hash []byte) error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if conn.currentMessage != message.None {
		return fmt.Errorf("cannot ask for sig shares in a currentMessage state different to None")
	}
	for _, node := range conn.nodes {
		message, err := node.AskForSigShare(keyID, hash)
		if err != nil {
			return fmt.Errorf("error asking sigshare with node %s: %s", node.GetID(), err)
		}
		conn.pendingMessages[message.ID] = message
	}
	conn.currentMessage = message.AskForSigShare
	return nil
}

// GetSigShares waits for the signatures the timeout set on the connection configuration.
// It returns only the sigshares that arrived before the timeout (they could be zero).
func (conn *ZMQ) GetSigShares() (tcrsa.SigShareList, error) {
	conn.mutex.Lock()
	defer func() {
		conn.pendingMessages = make(map[string]*message.Message)
		conn.currentMessage = message.None
		conn.mutex.Unlock()
	}()
	if conn.currentMessage != message.AskForSigShare {
		return nil, fmt.Errorf("cannot get sig shares in a currentMessage state different to askForSigShare")
	}
	sigShares := make(tcrsa.SigShareList, 0)
	timer := time.After(conn.timeout)
	minLen := 1
L:
	for {
		select {
		case msg := <-conn.channel:
			if pending, exists := conn.pendingMessages[msg.ID]; exists {
				if err := msg.Ok(pending, minLen); err != nil {
					log.Printf("error with message: %s\n", err)
					break
				}
				// Remove message from pending list
				delete(conn.pendingMessages, msg.ID)
				sigShare, err := message.DecodeSigShare(msg.Data[0])
				if err != nil {
					log.Printf("corrupt key: %v\n", msg)
					// Ask for it again?
					node := conn.GetNodeByID(msg.NodeID)
					newRequest, err := node.AskForSigShare(string(pending.Data[0]), pending.Data[1])
					if err != nil {
						log.Printf("error asking signature share to node %s: %s\n", node.GetID(), err)
					}
					// save it in pending
					conn.pendingMessages[newRequest.ID] = newRequest
				} else {
					sigShares = append(sigShares, sigShare)
					if len(sigShares) == len(conn.nodes) {
						log.Printf("all signature shares retrieved.\n")
						break L
					}
				}
			} else {
				log.Printf("unexpected message: %v\n", msg)
			}
		case <-timer:
			log.Printf("timeout: %d out of %d sigs retrieved\n", len(sigShares), len (conn.nodes))
			break L
		}
	}
	return sigShares, nil
}

// GetConnString returns a formatted connection string.
func (conn *ZMQ) GetConnString() string {
	return fmt.Sprintf("%s://%s:%d", TchsmProtocol, conn.ip, conn.port)
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
