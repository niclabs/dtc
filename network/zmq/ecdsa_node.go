package zmq

import (
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcecdsa"
	"math/big"
)

func (node *Node) sendECDSAKeyShare(id string, key *tcecdsa.KeyShare, meta *tcecdsa.KeyMeta) (*message.Message, error) {
	keyBinary, err := message.EncodeECDSAKeyShare(key)
	if err != nil {
		return nil, err
	}
	metaBinary, err := message.EncodeECDSAKeyMeta(meta)
	if err != nil {
		return nil, err
	}
	msg, err := message.NewMessage(message.SendECDSAKeyShare, node.getID(), []byte(id), keyBinary, metaBinary)
	if err != nil {
		return nil, err
	}
	_, err = node.socket.SendMessage(msg.GetBytesLists()...)
	if err != nil {
		return nil, err
	}
	return msg, nil

}

func (node *Node) ecdsaInitKeys(id string, initKeyMessages tcecdsa.KeyInitMessageList) (msg *message.Message, err error) {
	initKeyMsgsBin, err := message.EncodeECDSAKeyInitMessageList(initKeyMessages)
	if err != nil {
		return nil, err
	}
	msg, err = message.NewMessage(message.ECDSAInitKeys, node.getID(), []byte(id), initKeyMsgsBin)
	if err != nil {
		return nil, err
	}
	if _, err := node.socket.SendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) ecdsaRound1(id string, doc []byte) (msg *message.Message, err error) {
	msg, err = message.NewMessage(message.ECDSARound1, node.getID(), []byte(id), doc)
	if err != nil {
		return nil, err
	}
	if _, err := node.socket.SendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) ecdsaRound2(id string, messages tcecdsa.Round2MessageList) (msg *message.Message, err error) {
	msgsBin, err := message.EncodeECDSARound2MessageList(messages)
	if err != nil {
		return nil, err
	}
	msg, err = message.NewMessage(message.ECDSARound2, node.getID(), []byte(id), msgsBin)
	if err != nil {
		return nil, err
	}
	if _, err := node.socket.SendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) ecdsaRound3(id string, messages tcecdsa.Round3MessageList) (msg *message.Message, err error) {
	msgsBin, err := message.EncodeECDSARound3MessageList(messages)
	if err != nil {
		return nil, err
	}
	msg, err = message.NewMessage(message.ECDSARound3, node.getID(), []byte(id), msgsBin)
	if err != nil {
		return nil, err
	}
	if _, err := node.socket.SendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) ecdsaRound4(id string, r, s *big.Int) (msg *message.Message, err error) {
	msgsBin, err := message.EncodeECDSASignature(r, s)
	if err != nil {
		return nil, err
	}
	msg, err = message.NewMessage(message.ECDSAGetSIgnature, node.getID(), []byte(id), msgsBin)
	if err != nil {
		return nil, err
	}
	if _, err := node.socket.SendMessage(msg.GetBytesLists()...); err != nil {
		return nil, err
	}
	return msg, nil
}

func (node *Node) deleteECDSAKeyShare(id string) (*message.Message, error) {
	msg, err := message.NewMessage(message.DeleteECDSAKeyShare, node.getID(), []byte(id))
	if err != nil {
		return nil, err
	}
	_, err = node.socket.SendMessage(msg.GetBytesLists()...)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
