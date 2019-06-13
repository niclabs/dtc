package network

type Node interface {
	GetID() string
	GetError() error
	IsConnected() bool
	Disconnect() error
}
