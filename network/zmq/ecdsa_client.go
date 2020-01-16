package zmq

import (
	"fmt"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcecdsa"
	"log"
	"math/big"
)

func (client *Client) SendECDSAKeyShares(keyID string, keys []*tcecdsa.KeyShare, meta *tcecdsa.KeyMeta) error {
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
	i := 0
	for id, node := range client.nodes {
		log.Printf("Sending key share to node in %s:%d", node.host, node.port)
		msg, err := node.sendECDSAKeyShare(id, keys[i], meta)
		if err != nil {
			return fmt.Errorf("error with node %s: %s", id, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
		i++
	}
	client.currentMessage = message.SendECDSAKeyShare
	return nil
}

func (client *Client) GetECDSAKeyInitMessageList() (tcecdsa.KeyInitMessageList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.SendECDSAKeyShare {
		return nil, fmt.Errorf("cannot ask for KeyInitMessages in a currentMessage state different to SendECDSAKeyShare")
	}
	list := make(tcecdsa.KeyInitMessageList, 0)
	if err := doForNTimeout(client.channel, len(client.nodes), client.timeout, func(msg *message.Message) error {
		keyInitMsg, err := message.DecodeECDSAKeyInitMessage(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			list = append(list, keyInitMsg)
			return nil
		}
	}); err != nil {
		return nil, err
	}
	return list, nil
}

func (client *Client) SendECDSAKeyInitMessageList(keyID string, messages tcecdsa.KeyInitMessageList) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(messages) != len(client.nodes) {
		return fmt.Errorf("number of initKeyMessages is not equal to number of nodes")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send keyInitMessageList in a currentMessage state different to None")
	}
	for i, node := range client.nodes {
		log.Printf("Sending init key params to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaInitKeys(keyID, messages)
		if err != nil {
			return fmt.Errorf("error with node %d: %s", i, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.ECDSAInitKeys
	return nil
}

func (client *Client) AckECDSAKeyInitReception() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if !client.running {
		return fmt.Errorf("connection not running")
	}
	if client.currentMessage != message.ECDSAInitKeys {
		return fmt.Errorf("cannot ack KeyShareMessageList in a currentMessage state different to ECDSAInitKeys")
	}
	log.Printf("timeout will be %s", client.timeout)
	return doForNTimeout(client.channel, len(client.nodes), client.timeout, client.ackOnly)
}

func (client *Client) AskForECDSARound1MessageList(keyID string, msgToSign []byte) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot ask for Round1Message in a currentMessage state different to None")
	}
	for _, node := range client.nodes {
		log.Printf("Asking for sig share to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaRound1(keyID, msgToSign)
		if err != nil {
			return fmt.Errorf("error sending Round1Message with node %s: %s", node.id(), err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.ECDSARound1
	return nil
}

func (client *Client) GetECDSARound1MessageList(k int) ([]string, tcecdsa.Round1MessageList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if k <= 0 {
		return nil, nil, fmt.Errorf("k must be greater than 0")
	}
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.ECDSARound1 {
		return nil, nil, fmt.Errorf("cannot get Round1MessageList in a currentMessage state different to ECDSARound1")
	}
	list := make(tcecdsa.Round1MessageList, 0)
	msgIDs := make([]string, 0)
	if err := doForNTimeout(client.channel, k, client.timeout, func(msg *message.Message) error {
		keyInitMsg, err := message.DecodeECDSARound1Message(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			list = append(list, keyInitMsg)
			msgIDs = append(msgIDs, msg.NodeID)
			return nil
		}
	}); err != nil {
		return nil, nil, err
	}
	if len(list) != k || len(msgIDs) != k{
		return nil, nil, fmt.Errorf("list and msgIDs length should be k, but they are not")
	}
	return msgIDs, list, nil
}

func (client *Client) AskForECDSARound2MessageList(keyID string, nodeIDs []string, messages tcecdsa.Round1MessageList) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(messages) != len(nodeIDs) {
		return fmt.Errorf("number of Round1Messages is not equal to number of node IDs")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send Round1MessageList in a currentMessage state different to None")
	}
	for _, nodeID := range nodeIDs {
		node, ok := client.nodes[nodeID]
		if !ok {
			return fmt.Errorf("node with nodeID %s not found", nodeID)
		}
		log.Printf("Sending Round1MessageList to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaRound2(keyID, messages)
		if err != nil {
			return fmt.Errorf("error with node %s: %s", nodeID, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.ECDSARound2
	return nil
}

func (client *Client) GetECDSARound2MessageList(k int) (tcecdsa.Round2MessageList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if k <= 0 {
		return nil, fmt.Errorf("k must be greater than 0")
	}
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.ECDSARound2 {
		return nil, fmt.Errorf("cannot get Round2MessageList in a currentMessage state different to ECDSARound1")
	}
	list := make(tcecdsa.Round2MessageList, 0)
	if err := doForNTimeout(client.channel, k, client.timeout, func(msg *message.Message) error {
		keyInitMsg, err := message.DecodeECDSARound2Message(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			list = append(list, keyInitMsg)
			return nil
		}
	}); err != nil {
		return nil, err
	}
	if len(list) != k {
		return nil, fmt.Errorf("list length should be k, but it is not")
	}
	return list, nil
}

func (client *Client) AskForECDSARound3MessageList(keyID string, nodeIDs []string, messages tcecdsa.Round2MessageList) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(messages) != len(nodeIDs) {
		return fmt.Errorf("number of Round2Messages is not equal to number of node IDs")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send Round2MessageList in a currentMessage state different to None")
	}
	for _, nodeID := range nodeIDs {
		node, ok := client.nodes[nodeID]
		if !ok {
			return fmt.Errorf("node with nodeID %s not found", nodeID)
		}
		log.Printf("Sending Round2MessageList to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaRound3(keyID, messages)
		if err != nil {
			return fmt.Errorf("error with node %s: %s", nodeID, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.ECDSARound3
	return nil
}

func (client *Client) GetECDSARound3MessageList(k int) (tcecdsa.Round3MessageList, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if k <= 0 {
		return nil, fmt.Errorf("k must be greater than 0")
	}
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.ECDSARound3 {
		return nil, fmt.Errorf("cannot get Round3MessageList in a currentMessage state different to ECDSARound1")
	}
	list := make(tcecdsa.Round3MessageList, 0)
	if err := doForNTimeout(client.channel, k, client.timeout, func(msg *message.Message) error {
		keyInitMsg, err := message.DecodeECDSARound3Message(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			list = append(list, keyInitMsg)
			return nil
		}
	}); err != nil {
		return nil, err
	}
	if len(list) != k {
		return nil, fmt.Errorf("list length should be k, but it is not")
	}
	return list, nil
}

func (client *Client) AskForECDSASignature(keyID string, nodeIDs []string, messages tcecdsa.Round3MessageList) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if len(messages) != len(nodeIDs) {
		return fmt.Errorf("number of Round3Messages is not equal to number of node IDs")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot send Round3MessageList in a currentMessage state different to None")
	}
	for _, nodeID := range nodeIDs {
		node, ok := client.nodes[nodeID]
		if !ok {
			return fmt.Errorf("node with nodeID %s not found", nodeID)
		}
		log.Printf("Sending Round3MessageList to node in %s:%d", node.host, node.port)
		msg, err := node.ecdsaGetSignature(keyID, messages)
		if err != nil {
			return fmt.Errorf("error with node %s: %s", nodeID, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.ECDSAGetSignature
	return nil
}

func (client *Client) GetECDSASignature(k int) (*big.Int, *big.Int, error) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if k <= 0 {
		return nil, nil, fmt.Errorf("k must be greater than 0")
	}
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if client.currentMessage != message.ECDSAGetSignature {
		return nil, nil, fmt.Errorf("cannot get signature in a currentMessage state different to ECDSARound1")
	}
	rList := make([]*big.Int, 0)
	sList := make([]*big.Int, 0)
	if err := doForNTimeout(client.channel, k, client.timeout, func(msg *message.Message) error {
		r, s, err := message.DecodeECDSASignature(msg.Data[0])
		if err != nil {
			return fmt.Errorf("corrupt key: %v\n", msg)
		} else {
			rList = append(rList, r)
			sList = append(sList, s)
			return nil
		}
	}); err != nil {
		return nil, nil, err
	}
	if len(rList) != k || len(sList) != k {
		return nil, nil, fmt.Errorf("rList and sList length should be k, but they are not")
	}

	r := rList[0]
	s := sList[0]

	for _, ri := range rList {
		if ri.Cmp(r) != 0 {
			return nil, nil, fmt.Errorf("nodes returned different signatures")
		}
	}
	for _, si := range sList {
		if si.Cmp(s) != 0 {
			return nil, nil, fmt.Errorf("nodes returned different signatures")
		}
	}
	return r, s, nil
}

func (client *Client) AskForECDSAKeyDeletion(keyID string) error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot ask for key deletion in a currentMessage state different to None")
	}
	for _, node := range client.nodes {
		log.Printf("Asking for key deletion to node in %s:%d", node.host, node.port)
		msg, err := node.deleteECDSAKeyShare(keyID)
		if err != nil {
			return fmt.Errorf("error with node %s: %s", keyID, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.DeleteECDSAKeyShare
	return nil
}

func (client *Client) AckECDSAKeyDeletion() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if !client.running {
		return fmt.Errorf("connection not running")
	}
	if client.currentMessage != message.RestartECDSASession {
		return fmt.Errorf("cannot ack for key deletion in a currentMessage state different to ECDSAInitKeys")
	}
	log.Printf("timeout will be %s", client.timeout)
	return doForNTimeout(client.channel, len(client.nodes), client.timeout, client.ackOnly)
}

func (client *Client) AskForECDSASessionRestart() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if !client.running {
		return fmt.Errorf("connection not started")
	}
	if client.currentMessage != message.None {
		return fmt.Errorf("cannot ask for session restart in a currentMessage state different to None")
	}
	for id, node := range client.nodes {
		log.Printf("Asking for sesion restart to node in %s:%d", node.host, node.port)
		msg, err := node.restartECDSASession()
		if err != nil {
			return fmt.Errorf("error with node %s: %s", id, err)
		}
		client.pendingMessages[msg.ID] = msg
		go node.recvMessage()
	}
	client.currentMessage = message.RestartECDSASession
	return nil
}

func (client *Client) AckECDSASessionRestart() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	defer func() {
		client.pendingMessages = make(map[string]*message.Message)
		client.currentMessage = message.None
	}()
	if !client.running {
		return fmt.Errorf("connection not running")
	}
	if client.currentMessage != message.RestartECDSASession {
		return fmt.Errorf("cannot ack for session restart in a currentMessage state different to ECDSAInitKeys")
	}
	log.Printf("timeout will be %s", client.timeout)
	return doForNTimeout(client.channel, len(client.nodes), client.timeout, client.ackOnly)
}
