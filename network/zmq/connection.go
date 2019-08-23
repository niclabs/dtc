package zmq

import (
	"fmt"
	"github.com/niclabs/dtcnode/message"
	"github.com/niclabs/tcrsa"
	"github.com/pebbe/zmq4"
	"log"
	"sync"
	"time"
)

// The domain of the ZMQ connection. This value must be the same in the server, or it will not work.
const TchsmDomain = "tchsm"

// The protocol used for the ZMQ connection. TCP is the best for this usage cases.
const TchsmProtocol = "tcp"

// This error represents a timeout situation
var TimeoutError = fmt.Errorf("timeout")

// Client Structure represents a connection to a set of Nodes via ZMQ
// Messaging Protocol.
type Client struct {
	ID              string                      // Connection ID
	running         bool                        // true if it is running
	privKey         string                      // Private Key of node
	pubKey          string                      // Public Key of node
	timeout         time.Duration               // Length of timeout in seconds
	nodes           []*Node                     // List of connected nodes of type ZMQ
	ctx             *zmq4.Context               // ZMQ Context
	pendingMessages map[string]*message.Message // A map with requests without response. To know what messages I'm expecting.
	channel         chan *message.Message       // The channel where all the responses from router are sent.
	mutex           sync.Mutex                  // A mutex to operate the pendingMessages map.
	currentMessage  message.Type                // A label which indicates the operation the connection is doing right now. It avoids inconsistent states (i.e. ask for a type of resource and then collect another one).
}

// New returns a new ZMQ connection based in the configuration provided.
func New(config *Config) (client *Client, err error) {
	context, err := zmq4.NewContext()
	if err != nil {
		return
	}
	if config.Timeout == 0 {
		config.Timeout = 10
	}
	clientID, err := message.GetRandomHexString(8)
	if err != nil {
		return nil, err
	}
	client = &Client{
		ID:              clientID,
		privKey:         config.PrivateKey,
		pubKey:          config.PublicKey,
		timeout:         time.Duration(config.Timeout) * time.Second,
		ctx:             context,
		channel:         make(chan *message.Message),
		pendingMessages: make(map[string]*message.Message),
		nodes:           make([]*Node, 0),
	}
	for i := 0; i < len(config.Nodes); i++ {
		newNode, err := newNode(client, config.Nodes[i])
		if err != nil {
			return nil, fmt.Errorf("Node number %i has a bad configuration", i+1)
		}
		client.nodes = append(client.nodes, newNode)
	}
	return
}

func (client *Client) Open() (err error) {
	if client.running {
		return nil
	}
	if client.nodes == nil {
		return fmt.Errorf("not initialized. Use 'New' to create a new struct")
	}
	_ = zmq4.AuthStart()
	// Now we connect to the clients
	for _, node := range client.nodes {
		if err = node.connect(); err != nil {
			zmq4.AuthStop()
			return
		}
	}
	client.running = true
	return
}

func (client *Client) Close() error {
	if !client.running {
		return nil
	}
	// Try to disconnect from peers
	for _, node := range client.nodes {
		err := node.disconnect()
		if err != nil {
			return err
		}
	}
	client.running = false
	zmq4.AuthStop()
	return nil
}

func (client *Client) SendKeyShares(keyID string, keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(keys) != len(client.nodes) {
		return fmt.Errorf("number of keys is not equal to number of nodes")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send key shares in a currentMessage state different to None")
	}
	for i, node := range client.nodes {
		log.Printf("Sending key share to node in %s:%d", node.host, node.port)
		msg, err := node.sendKeyShare(keyID, keys[i], meta)
		if err != nil {
			return fmt.Errorf("error with node %d: %s", i, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.SendKeyShare
	return nil
}

func (client *Client) AckKeyShares() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if !client.running {
		return fmt.Errorf("connection not running")
	}
	if client.currentMessage != message.SendKeyShare {
		return fmt.Errorf("cannot ack key shares in a currentMessage state different to sendKeyShare")
	}
	acked := 0
	log.Printf("timeout will be %s", client.timeout)
	timer := time.After(client.timeout)
	for {
		select {
		case msg := <-client.channel:
			log.Printf("message received from node %s\n", msg.NodeID)
			if pending, exists := client.pendingMessages[msg.ID]; exists {
				if err := msg.Ok(pending, 0); err != nil {
					log.Printf("error with message from node %s: %v\n", msg.NodeID, message.ErrorToString[msg.Error])
				}
				delete(client.pendingMessages, msg.ID)
				acked++
				if acked == len(client.nodes) {
					return nil
				}
			} else {
				log.Printf("unexpected message: %+v\n", msg)
			}
		case <-timer:
			return TimeoutError
		}
	}
}

func (client *Client) AskForSigShares(keyID string, hash []byte) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot ask for sig shares in a currentMessage state different to None")
	}
	for _, node := range client.nodes {
		log.Printf("Asking for sig share to node in %s:%d", node.host, node.port)
		msg, err := node.askForSigShare(keyID, hash)
		if err != nil {
			return fmt.Errorf("error asking sigshare with node %s: %s", node.getID(), err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.AskForSigShare
	return nil
}

func (client *Client) GetSigShares() (tcrsa.SigShareList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.AskForSigShare {
		return nil, fmt.Errorf("cannot get sig shares in a currentMessage state different to askForSigShare")
	}
	sigShares := make(tcrsa.SigShareList, 0)
	timer := time.After(client.timeout)
	minLen := 1
L:
	for {
		select {
		case msg := <-client.channel:
			if pending, exists := client.pendingMessages[msg.ID]; exists {
				if err := msg.Ok(pending, minLen); err != nil {
					log.Printf("error with message: %s\n", err)
					break
				}
				// Remove message from pending list
				delete(client.pendingMessages, msg.ID)
				sigShare, err := message.DecodeSigShare(msg.Data[0])
				if err != nil {
					log.Printf("corrupt key: %v\n", msg)
				} else {
					sigShares = append(sigShares, sigShare)
					if len(sigShares) == len(client.nodes) {
						log.Printf("all signature shares retrieved.\n")
						break L
					}
				}
			} else {
				log.Printf("unexpected message: %v\n", msg)
			}
		case <-timer:
			log.Printf("timeout: %d out of %d sigs retrieved\n", len(sigShares), len(client.nodes))
			break L
		}
	}
	return sigShares, nil
}

func (client *Client) AskForKeyDeletion(keyID string) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot delete key shares in a currentMessage state different to None")
	}
	for i, node := range client.nodes {
		log.Printf("Sending key share deletion petition to node in %s:%d", node.host, node.port)
		msg, err := node.deleteKeyShare(keyID)
		if err != nil {
			return fmt.Errorf("error with node %d: %s", i, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.DeleteKeyShare
	return nil
}

func (client *Client) GetKeyDeletionAck() (int, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.DeleteKeyShare {
		return 0, fmt.Errorf("cannot ack key share deletions in a currentMessage state different to DeleteKeyShare")
	}
	acked := 0
	log.Printf("timeout will be %s", client.timeout)
	timer := time.After(client.timeout)
	for {
		select {
		case msg := <-client.channel:
			log.Printf("message received from node %s\n", msg.NodeID)
			if pending, exists := client.pendingMessages[msg.ID]; exists {
				if err := msg.Ok(pending, 0); err != nil {
					log.Printf("error with message from node %s: %v\n", msg.NodeID, message.ErrorToString[msg.Error])
				}
				delete(client.pendingMessages, msg.ID)
				acked++
				if acked == len(client.nodes) {
					return acked, nil
				}
			} else {
				log.Printf("unexpected message: %+v\n", msg)
			}
		case <-timer:
			return acked, TimeoutError
		}
	}
}

func (client *Client) getPubKeys() []string {
	pubKeys := make([]string, len(client.nodes))
	for i, node := range client.nodes {
		pubKeys[i] = node.pubKey
	}
	return pubKeys
}

func (client *Client) getIPs() ([]string, error) {
	ips := make([]string, len(client.nodes))
	for i, node := range client.nodes {
		ips[i] = node.host.String()
	}
	return ips, nil
}

func (client *Client) getNodeByID(id string) *Node {
	for _, node := range client.nodes {
		if node.getID() == id {
			return node
		}
	}
	return nil
}
