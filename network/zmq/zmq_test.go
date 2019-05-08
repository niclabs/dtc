package zmq

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"github.com/niclabs/tcrsa"
	"github.com/pebbe/zmq4"
	"testing"
)

const testK = 6
const testL = 10

type NodeStub struct {
	privKey string
	pubKey  string
	ip      string
	port    uint16
	server  *ZMQ
	context *zmq4.Context
	socket  *zmq4.Socket
}

func (stub *NodeStub) GetID() string {
	return fmt.Sprintf("node-%d", stub.port)
}

// This should be launched as goroutine
func (stub *NodeStub) StartAndWait(connPubKey string) error {
	zmq4.AuthAllow(stub.GetID(), "127.0.0.1")
	zmq4.AuthCurveAdd(stub.GetID(), connPubKey)

	conn, err := zmq4.NewSocket(zmq4.SUB)
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
	if err := conn.Bind(fmt.Sprintf("tcp://%s:%d", stub.ip, stub.port)); err != nil {
		return err
	}

	for {
		rawMsg, err := conn.RecvMessageBytes(0)
		if err != nil {
			return err
		}
		if len(rawMsg) < 2 || len(rawMsg[0]) != 1 {
			return fmt.Errorf("wrong message")
		}
		msgType := rawMsg[0]
		msgRest := rawMsg[1:]

		var keyShare *tcrsa.KeyShare
		var keyMeta *tcrsa.KeyMeta

		switch msgType[0] {
		case SendKeyShare:
			keyBuffer := bytes.NewBuffer(msgRest[0])
			keyDecoder := gob.NewDecoder(keyBuffer)
			if err = keyDecoder.Decode(keyShare); err != nil {
				return err
			}
			metaBuffer := bytes.NewBuffer(msgRest[1])
			metaDecoder := gob.NewDecoder(metaBuffer)
			if err = metaDecoder.Decode(keyMeta); err != nil {
				_, _ = conn.SendMessage([][]byte{{SendKeyShare}, []byte("okn't")}, 0)
				return err
			}
			_, err := conn.SendMessage([][]byte{{SendKeyShare}, []byte("ok")}, 0)
			if err != nil {
				return err
			}
		case GetSigShare:
			if keyShare == nil || keyMeta == nil {
				_, _ = conn.SendMessage([][]byte{{GetSigShare}, []byte("okn't")}, 0)
				return err
			}
			respBuffer := bytes.NewBuffer(msgRest[0])
			sigDecoder := gob.NewDecoder(respBuffer)
			var doc []byte
			if err = sigDecoder.Decode(&doc); err != nil {
				return err
			}
			sigShare, err := keyShare.Sign(doc, crypto.SHA256, keyMeta)
			if err != nil {
				_, _ = conn.SendMessage([][]byte{{GetSigShare}, []byte("okn't")}, 0)
				return err
			}
			var keyBuffer bytes.Buffer
			keyEncoder := gob.NewEncoder(&keyBuffer)
			if err := keyEncoder.Encode(sigShare); err != nil {
				return err
			}
			flagBinary := []byte{GetSigShare}
			keyBinary := keyBuffer.Bytes()
			completeMsg := [][]byte{flagBinary, keyBinary}
			_, err = conn.SendMessage(completeMsg, 0)
			if err != nil {
				return err
			}
			// we stop the server after signing
			return nil
		default:
			return fmt.Errorf("unknown message")
		}
	}
}

func getNodeStubs(num uint16) (nodeStubs []*NodeStub, err error) {
	context, err := zmq4.NewContext()
	if err != nil {
		return
	}
	initPort := uint16(2031)
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
	return
}

func getExampleConfig(numNodes uint16) (config *Config, stubs []*NodeStub, err error) {
	config = &Config{
		IP:    "127.0.0.1",
		Port:  2030,
		Nodes: make([]*NodeConfig, numNodes),
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
	conn, nodes, err := createConnection()
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// We start the nodes
	for _, node := range nodes {
		go func() {
			err := node.StartAndWait(conn.pubKey)
			if err != nil {
				t.Errorf("%v", err)
			}
		}()
	}

	// and open the connection
	err = conn.Open()
	defer conn.Close()
	if err != nil {
		t.Errorf("cannot close connection: %v", err)
		return
	}

	// Extracted from libtdc documentation

	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(testK), uint16(testL), nil)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	// Sending keys

	for i, node := range conn.GetNodes() {
		err := node.SendKeyShare(keyShares[i], keyMeta,10)
		if err != nil {
			t.Errorf("cannot send key share: %v", err)
		}
	}

	// Hashing a doc (hello world)
	docHash := sha256.Sum256([]byte("hello world"))
	docPKCS1, err := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	// Asking for signatures
	sigShares := make(tcrsa.SigShareList, testL)
	for i, node := range conn.GetNodes() {
		sigShares[i], err = node.Sign(docPKCS1, 10)
		if err != nil {
			t.Errorf("cannot create sig share: %v", err)
		}
		if err := sigShares[i].Verify(docPKCS1, keyMeta); err != nil {
			t.Errorf(fmt.Sprintf("sig share received is invalid: %v", err))
		}
	}

	// Finally we join them.

	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}

}
