package message

import (
	"fmt"
)

type Message struct {
	NodeID string
	ID     string
	Type   Type
	Error  NodeError
	Data   [][]byte
}

func FromBytes(rawMsg [][]byte) (*Message, error) {
	if len(rawMsg) < 4 { // header is dealer ID, rest is message struct.
		return nil, fmt.Errorf("bad byte array length")
	}
	return &Message{
		NodeID: string(rawMsg[0]), // Provided by
		ID:     string(rawMsg[1]),
		Type:   Type(rawMsg[2][0]),
		Error:  NodeError(rawMsg[3][0]),
		Data:   rawMsg[4:],
	}, nil
}

func NewMessage(rType Type, nodeID string, msgs ...[]byte) (*Message, error) {
	id, err := GetRandomHexString(6)
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
		return fmt.Errorf("node ID mismatch: got: %s, expected: %s", message.NodeID, message2.NodeID)
	}
	if message.Type != message2.Type {
		return fmt.Errorf("type mismatch: got: %s, expected: %s", message.Type, message2.Type)
	}
	if message.Error != Ok {
		return fmt.Errorf("response has error: %s", message.Error.Error())
	}
	if len(message.Data) < minDataLen {
		return fmt.Errorf("data length mismatch: got: %d, expected at least: %d", len(message.Data), minDataLen)
	}
	return nil
}
