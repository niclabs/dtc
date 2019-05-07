package zmq

import "github.com/pebbe/zmq4"

type ConnNode struct {
	PubSocket zmq4.Socket
}
