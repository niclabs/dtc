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


func (message *Message) Ok(message2 *Message, minDataLen int) error {
	if message.ID != message2.ID  {
		return fmt.Errorf("ID mismatch: got: %s, expected: %s", message.ID, message2.ID)
	}
	if message.NodeID != message2.NodeID {
		return fmt.Errorf("Node ID mismatch: got: %s, expected: %s", message.NodeID, message2.NodeID)
	}
	if message.Type != message2.Type {
		return fmt.Errorf("Type mismatch: got: %s, expected: %s", message.Type, message2.Type)
	}
	if message.Error != NoError {
		return fmt.Errorf("Response has error: %s", message.Error.Error())
	}
	if len(message.Data) < minDataLen {
		return fmt.Errorf("Data Length mismatch: got: %d, expected at least: %d", len(message.Data), minDataLen)
	}
	return nil
}
