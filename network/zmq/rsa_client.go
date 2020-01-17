package zmq

import (
	"fmt"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcrsa"
	"log"
)

func (client *Client) SendRSAKeyShares(keyID string, keys tcrsa.KeyShareList, meta *tcrsa.KeyMeta) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(keys) != len(client.nodes) {
		return fmt.Errorf("number of keys (%d) is not equal to number of nodes (%d)", len(keys), len(client.nodes))
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send key shares in a currentMessage state different to None")
	}
	i := 0
	for _, node := range client.nodes {
		log.Printf("Sending key share to node in %s:%d", node.host, node.port)
		msg, err := node.sendRSAKeyShare(keyID, keys[i], meta)
		if err != nil {
			return fmt.Errorf("error with node %d: %s", i, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
		i++
	}
	client.currentMessage = message.SendRSAKeyShare
	return nil
}

func (client *Client) AckRSAKeyShares() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if !client.running {
		return fmt.Errorf("connection not running")
	}
	if client.currentMessage != message.SendRSAKeyShare {
		return fmt.Errorf("cannot ack key shares in a currentMessage state different to sendRSAKeyShare")
	}
	log.Printf("timeout will be %s", client.timeout)
	return doForNTimeout(client.channel, len(client.nodes), client.timeout, client.ackOnly)
}

func (client *Client) AskForRSASigShares(keyID string, hash []byte) error {
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
		msg, err := node.getRSASigShare(keyID, hash)
		if err != nil {
			return fmt.Errorf("error asking sigshare with node %s: %s", node.ID(), err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.GetRSASigShare
	return nil
}

func (client *Client) GetRSASigShares(k int) (tcrsa.SigShareList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.GetRSASigShare {
		return nil, fmt.Errorf("cannot get sig shares in a currentMessage state different to getRSASigShare")
	}
	sigShares := make(tcrsa.SigShareList, 0)
	if err := doForNTimeout(client.channel, k, client.timeout, func(msg *message.Message) error {
		sigShare, err := message.DecodeRSASigShare(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			sigShares = append(sigShares, sigShare)
			return nil
		}
	}); err != nil {
		return nil, err
	}
	return sigShares, nil
}

func (client *Client) AskForRSAKeyDeletion(keyID string) error {
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
		msg, err := node.deleteRSAKeyShare(keyID)
		if err != nil {
			return fmt.Errorf("error with node %d: %s", i, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.DeleteRSAKeyShare
	return nil
}

func (client *Client) AckRSAKeyDeletion() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.DeleteRSAKeyShare {
		return fmt.Errorf("cannot ack key share deletions in a currentMessage state different to DeleteKeyShare")
	}
	log.Printf("timeout will be %s", client.timeout)
	return doForNTimeout(client.channel, len(client.nodes), client.timeout, client.ackOnly)
}
