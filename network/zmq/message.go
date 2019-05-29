package zmq

import (
	"dtcmaster/network"
	"dtcmaster/utils"
	"fmt"
)

type Message struct {
	ID     string
	Type   network.MessageType
	NodeID string
	Error  NodeError
	Data   [][]byte
}

func MessageFromBytes(rawMsg [][]byte) (*Message, error) {
	if len(rawMsg) < 4 {
		return nil, fmt.Errorf("bad byte array length")
	}
	return &Message{
		ID:     string(rawMsg[0]),
		Type:   network.MessageType(rawMsg[1][0]),
		NodeID: string(rawMsg[2]),
		Error:  NodeError(rawMsg[3][0]),
		Data:   rawMsg[4:],
	}, nil
}

func NewMessage(rType network.MessageType, nodeID string, msgs ...[]byte) (*Message, error) {
	id, err := utils.GetRandomHexString(6)
	if err != nil {
		return nil, err
	}
	req := &Message{
		ID:     id,
		Type:   rType,
		NodeID: nodeID,
		Data:   make([][]byte, len(msgs)),
	}
	req.Data = append(req.Data, msgs...)
	return req, nil
}

func (message *Message) GetBytesLists() [][]byte {
	b := [][]byte{
		[]byte(message.ID),
		{byte(message.Type)},
		[]byte(message.NodeID),
		{byte(message.Error)},
	}
	b = append(b, message.Data...)
	return b
}

func (message *Message) AddMessage(data []byte) {
	message.Data = append(message.Data, data)
}

func (message *Message) CopyWithoutData(status NodeError) *Message {
	return &Message{
		ID:     message.ID,
		NodeID: message.NodeID,
		Type:   message.Type,
		Error:  status,
		Data:   make([][]byte, 0),
	}
}


func (message *Message) Ok(message2 *Message) bool {
	return message.ID == message2.ID &&
		message.NodeID == message2.NodeID &&
		message.Type == message2.Type &&
		message.Error == NoError
}
