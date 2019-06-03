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
		Data:   make([][]byte, 0),
	}
	req.Data = append(req.Data, msgs...)
	return req, nil
}

func (message *Message) GetBytesLists() []interface{} {
	b := []interface{}{
		[]byte(message.ID),
		[]byte{byte(message.Type)},
		[]byte(message.NodeID),
		[]byte{byte(message.Error)},
	}
	for _, datum := range message.Data {
		b = append(b, datum)
	}
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
