package zmq

import(
	"github.com/pebbe/zmq4"
	zmq42 "github.com/pebbe/zmq4/draft"
)

type Connection struct {
	config Config
	serverSocket *zmq4.Socket
	nodes []*ConnNode
}


func New(config Config) *Connection {
	return &Connection {
		config: config,
		nodes: make([]*ConnNode, 0),
	}
}

func (conn *Connection) OpenConnection() (err error) {
	// Create SubSocket
	socket, err := zmq4.NewSocket(zmq42.SERVER)
	if err != nil {
		return
	}
	conn.serverSocket = socket
	err = conn.serverSocket.Bind(conn.config.Network.String())
	if err != nil {
		return
	}
	// Create node from each node
}