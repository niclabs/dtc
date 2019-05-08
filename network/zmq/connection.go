package zmq

import(
	"dtcmaster/network"
	"fmt"
	"github.com/pebbe/zmq4"
	"net"
)

const TchsmDomain = "tchsm"

type ZMQ struct {
	ip           net.IP
	port         uint16
	privKey      string
	pubKey       string
	serverSocket *zmq4.Socket
	nodes        []*Node
	ctx          *zmq4.Context
}

func New(config *Config) (conn *ZMQ, err error) {
	nodes := make([]*Node, len(config.Nodes))
	for i := 0; i < len(config.Nodes); i++ {
		nodes[i] = &Node{
			ip:     net.ParseIP(config.Nodes[i].IP),
			port:   config.Nodes[i].Port,
			pubKey: config.Nodes[i].PublicKey,
			conn:   conn,
		}
	}
	context, err := zmq4.NewContext()
	if err != nil {
		return
	}
	conn = &ZMQ{
		ip:      net.ParseIP(config.IP),
		port:    config.Port,
		nodes:   nodes,
		pubKey:  config.PublicKey,
		privKey: config.PrivateKey,
		ctx:     context,
	}
	return
}

func (conn *ZMQ) Open() (err error) {
	err = zmq4.AuthStart()
	if err != nil {
		return
	}
	// Create socket
	socket, err := conn.ctx.NewSocket(zmq4.ROUTER)
	if err != nil {
		return
	}
	conn.serverSocket = socket

	// Add all IPs in domain as allowed
	err = conn.serverSocket.ServerAuthCurve(TchsmDomain, conn.privKey)
	if err != nil {
		return
	}

	// Bind
	err = conn.serverSocket.Bind(conn.GetConnString())
	if err != nil {
		return
	}

	// Add peers to auth curve allowed and try to connect to them
	for _, node := range conn.nodes {
		zmq4.AuthCurveAdd(TchsmDomain, node.pubKey)
		node.Connect()
	}
	return
}

func (conn *ZMQ) GetConnString() string {
	return fmt.Sprintf("tcp://%s:%d", conn.ip, conn.port)
}

func (conn *ZMQ) GetNodes() (nodes []network.Node) {
	nodes = make([]network.Node, 0)
	for _, node := range conn.nodes {
		nodes = append(nodes, node)
	}
	return
}

func (conn *ZMQ) GetActiveNodes() (nodes []network.Node) {
	nodes = make([]network.Node, 0)
	for _, node := range conn.nodes {
		if node.Err == nil {
			nodes = append(nodes, node)
		}
	}
	return
}

func (conn *ZMQ) Close() error {
	err := conn.serverSocket.Disconnect(conn.GetConnString())
	if err != nil {
		return err
	}
	// Try to connect to peers
	for _, node := range conn.nodes {
		err = node.Disconnect()
		if err != nil {
			return err
		}
	}
	zmq4.AuthStop()
	return nil
}