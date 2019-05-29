package zmq

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"dtcmaster/network"
	"encoding/gob"
	"fmt"
	"github.com/niclabs/tcrsa"
	"github.com/pebbe/zmq4"
	"os"
	"testing"
)

const testK = 6
const testL = 10

var initPort uint16 = 2031

type NodeStub struct {
	privKey string
	pubKey  string
	ip      string
	port    uint16
	context *zmq4.Context
}

func (stub *NodeStub) GetID() string {
	return fmt.Sprintf("node-%d", stub.port)
}

// This should be launched as goroutine
func (stub *NodeStub) StartAndWait(connPubKey string) error {
	conn, err := stub.context.NewSocket(zmq4.SUB)
	defer func() {
		conn.SetLinger(0)
		conn.Close()
	}()
	if err != nil {
		return err
	}
	if err := conn.SetIdentity(stub.GetID()); err != nil {
		return err
	}
	if err := conn.ServerAuthCurve(stub.GetID(), stub.privKey); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "connecting to tcp://%s:%d...\n", stub.ip, stub.port)
	if err := conn.Bind(fmt.Sprintf("tcp://%s:%d", stub.ip, stub.port)); err != nil {
		return err
	}

	for {
		var keyShare *tcrsa.KeyShare
		var keyMeta *tcrsa.KeyMeta
		_, _ = fmt.Fprintf(os.Stderr, "stub %s: receiving message...\n", stub.GetID())
		rawMsg, err := conn.RecvMessageBytes(0)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, ReceiveMessageError.ComposeError(err))
			continue
		}
		_, _ = fmt.Fprintf(os.Stderr, "stub %s: parsing message...\n", stub.GetID())
		msg, err := MessageFromBytes(rawMsg)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, ParseMessageError.ComposeError(err))
			continue
		}
		_, _ = fmt.Fprintf(os.Stderr, "stub %s: copying response...\n", stub.GetID())
		resp := msg.CopyWithoutData(NoError)
		switch msg.Type {
		case network.SendKeyShare:
			_, _ = fmt.Fprintf(os.Stderr, "stub %s: parsing keyshare...\n", stub.GetID())
			if err = gob.NewDecoder(bytes.NewBuffer(msg.Data[0])).Decode(keyShare); err != nil {
				resp.Error = KeyShareDecodeError
				break
			}
			_, _ = fmt.Fprintf(os.Stderr, "stub %s: parsing keymeta...\n", stub.GetID())
			if err = gob.NewDecoder(bytes.NewBuffer(msg.Data[1])).Decode(keyMeta); err != nil {
				resp.Error = KeyMetaDecodeError
				break
			}
		case network.AskForSigShare:
			if keyShare == nil || keyMeta == nil {
				_, _ = fmt.Fprintf(os.Stderr, "stub %s: not initialized ...\n", stub.GetID())
				resp.Error = NotInitializedError
				break
			}
			var doc []byte
			_, _ = fmt.Fprintf(os.Stderr, "stub %s: parsing message...\n", stub.GetID())
			if err = gob.NewDecoder(bytes.NewBuffer(msg.Data[0])).Decode(&doc); err != nil {
				resp.Error = DocDecodeError
				break
			}
			// Sign
			_, _ = fmt.Fprintf(os.Stderr, "stub %s: signing message ...\n", stub.GetID())
			sigShare, err := keyShare.Sign(doc, crypto.SHA256, keyMeta)
			if err != nil {
				resp.Error = DocSignError
				break
			}
			var keyBuffer bytes.Buffer
			_, _ = fmt.Fprintf(os.Stderr, "stub %s: encoding sigshare ...\n", stub.GetID())
			if err := gob.NewEncoder(&keyBuffer).Encode(sigShare); err != nil {
				resp.Error = SigShareEncodeError
				break
			}
		default:
			resp.Error = UnknownError
		}
		if resp.Error != NoError {
			_, _ = fmt.Fprintf(os.Stderr, resp.Error.ComposeError(err))
		}
		_, _ = fmt.Fprintf(os.Stderr, "stub %s: sending message ...\n", stub.GetID())
		_, err = conn.SendMessage(resp)
		if err != nil {
			resp.Error = SendResponseError
			_, _ = fmt.Fprintf(os.Stderr, resp.Error.ComposeError(err))
		}
		// In this mock up, we stop the server after signing and sending successfully
		if resp.Error == NoError && resp.Type == network.AskForSigShare {
			break
		}
	}
	return nil
}

func getNodeStubs(num uint16) (nodeStubs []*NodeStub, err error) {
	context, err := zmq4.NewContext()
	if err != nil {
		return
	}
	nodeStubs = make([]*NodeStub, num)
	var i uint16
	for i = 0; i < num; i++ {
		nodeStubs[i] = &NodeStub{
			ip:      "127.0.0.1",
			port:    initPort + i,
			context: context,
		}
		pubKey, privKey, err1 := zmq4.NewCurveKeypair()
		if err1 != nil {
			err = err1
			return
		}
		nodeStubs[i].pubKey, nodeStubs[i].privKey = pubKey, privKey
	}
	// update initport number for future uses
	initPort += num
	return
}

func getExampleConfig(numNodes uint16) (config *Config, stubs []*NodeStub, err error) {
	config = &Config{
		IP:    "127.0.0.1",
		Port:  2030,
		Nodes: make([]*NodeConfig, numNodes),
		Timeout: 3,
	}
	pubKey, privKey, err := zmq4.NewCurveKeypair()
	if err != nil {
		return
	}
	config.PublicKey, config.PrivateKey = pubKey, privKey

	stubs, err = getNodeStubs(numNodes)
	if err != nil {
		return
	}
	for i, stub := range stubs {
		config.Nodes[i] = &NodeConfig{
			IP:        stub.ip,
			Port:      stub.port,
			PublicKey: stub.pubKey,
		}
	}
	return
}

func createConnection() (conn *ZMQ, nodes []*NodeStub, err error) {

	config, nodes, err := getExampleConfig(testL)
	if err != nil {
		return
	}
	conn, err = New(config)
	return
}

func TestNew(t *testing.T) {
	_, _, err := createConnection()
	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestZMQ_Open(t *testing.T) {
	conn, _, err := createConnection()
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	err = conn.Open()
	defer conn.Close()
	if err != nil {
		t.Errorf("%v", err)
		return
	}
}

func TestZMQ_Connect(t *testing.T) {
	_, _ = fmt.Fprintf(os.Stderr, "server: creating connection...\n")
	conn, nodes, err := createConnection()
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// We start the nodes
	_, _ = fmt.Fprintf(os.Stderr, "server: starting the nodes...\n")
	for i := 0; i < len(nodes); i++ {
		node := nodes[i]
		zmq4.AuthAllow(node.GetID(), "127.0.0.1")
		zmq4.AuthCurveAdd(node.GetID(), conn.pubKey)
		go func() {
			err := node.StartAndWait(conn.pubKey)
			if err != nil {
				t.Errorf("%v", err)
			}
		}()
	}

	// and open the connection
	_, _ = fmt.Fprintf(os.Stderr, "server: starting the server node...\n")
	err = conn.Open()
	defer conn.Close()
	if err != nil {
		t.Errorf("cannot close connection: %v", err)
		return
	}

	// Extracted from libtdc documentation
	_, _ = fmt.Fprintf(os.Stderr, "server: creating the keys...\n")
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(testK), uint16(testL), nil)
	if err != nil {
		t.Errorf("cannot create keys: %v", err)
		return
	}

	// Sending keys
	_, _ = fmt.Fprintf(os.Stderr, "server: sending the keys...\n")
	if err := conn.SendKeyShares(keyShares, keyMeta); err != nil {
		t.Errorf("cannot send key shares: %v", err)
		return
	}

	// Receiving acks
	_, _ = fmt.Fprintf(os.Stderr, "server: waiting for acks...\n")

	if err := conn.AckKeyShares(); err != nil {
		t.Errorf("error acking key shares: %v", err)
		return
	}

	_, _ = fmt.Fprintf(os.Stderr, "server: hashing the doc...\n")
	// Hashing a doc (hello world)
	docHash := sha256.Sum256([]byte("hello world"))

	// PKCS1 Padding
	_, _ = fmt.Fprintf(os.Stderr, "server: padding the hash of the doc...\n")

	docPKCS1, err := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		t.Errorf("error preparing hash: %v", err)
		return
	}

	// Asking for signatures
	_, _ = fmt.Fprintf(os.Stderr, "server: asking for sigshares...\n")
	if err := conn.AskForSigShares(docPKCS1); err != nil {
		t.Errorf("error asking for sigshares: %v", err)
		return
	}

	// Retrieving signatures
	_, _ = fmt.Fprintf(os.Stderr, "server: retrieving sigshares...\n")

	sigShares, err :=  conn.GetSigShares()
	if err != nil {
		t.Errorf("error retrieving sigshares: %v", err)
		return
	}

	if len(sigShares) < testK {
		t.Errorf("there are no enough sigshares")
		return
	}
	// Finally we join them.
	_, _ = fmt.Fprintf(os.Stderr, "server: joining sigshares...\n")
	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
		return
	}

	_, _ = fmt.Fprintf(os.Stderr, "server: verifying signature...\n")
	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
		return
	}

}
