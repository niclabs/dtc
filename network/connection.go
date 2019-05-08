package network

type Connection interface{
	Open() error
	GetNodes() []Node
	GetActiveNodes() []Node
	Close() error
}