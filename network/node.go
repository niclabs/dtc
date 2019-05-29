package network


type MessageType uint8

const (
	None MessageType = iota
	SendKeyShare
	AskForSigShare
)

type Node interface {
	GetID() string
	GetError() error
	IsConnected() bool
	Disconnect() error
}