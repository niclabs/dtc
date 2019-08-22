package zmq

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/niclabs/dtcnode/message"
	"github.com/niclabs/tcrsa"
	"github.com/pebbe/zmq4"
	"testing"
	"time"
)

const testK = 6
const testL = 10
const testIP = "0.0.0.0"
const testTimeout = 5
const testKeyID = "testkey"

var initPort uint16 = 2030

type NodeStub struct {
	privKey string
	pubKey  string
	ip      string
	port    uint16
	context *zmq4.Context
}

func init() {
	zmq4.AuthSetVerbose(true)
}

func (stub *NodeStub) GetID() string {
	return stub.pubKey
}

func (stub *NodeStub) GetConnString() string {
	return fmt.Sprintf("%s://%s:%d", TchsmProtocol, stub.ip, stub.port)
}

// This should be launched as goroutine
func (stub *NodeStub) StartAndWait(server *Server, t *testing.T) error {
	in, err := stub.context.NewSocket(zmq4.ROUTER)
	if err != nil {
		return err
	}
	out, err := stub.context.NewSocket(zmq4.DEALER)
	if err != nil {
		return err
	}
	defer func() {
		in.SetLinger(0)
		in.Close()
		out.SetLinger(0)
		out.Close()
	}()
	if err := in.ServerAuthCurve(TchsmDomain, stub.privKey); err != nil {
		return err
	}
	if err := in.Bind(stub.GetConnString()); err != nil {
		return err
	}

	if err := out.SetIdentity(stub.GetID()); err != nil {
		return err
	}
	if err := out.ClientAuthCurve(server.pubKey, stub.pubKey, stub.privKey); err != nil {
		return err
	}
	if err := out.Connect(server.getConnString()); err != nil {
		return err
	}

	var keyShare *tcrsa.KeyShare
	var keyMeta *tcrsa.KeyMeta
	for {
		rawMsg, err := in.RecvMessageBytes(0)
		if err != nil {
			continue
		}
		msg, err := message.FromBytes(rawMsg)
		if err != nil {
			continue
		}
		resp := msg.CopyWithoutData(message.Ok)
		switch msg.Type {
		case message.SendKeyShare:
			if len(msg.Data) != 3 || string(msg.Data[0]) != testKeyID {
				resp.Error = message.InvalidMessageError
				break
			}
			keyShare, err = message.DecodeKeyShare(msg.Data[1])
			if err != nil {
				resp.Error = message.KeyShareDecodeError
				break
			}
			keyMeta, err = message.DecodeKeyMeta(msg.Data[2])
			if err != nil {
				resp.Error = message.KeyMetaDecodeError
				break
			}
		case message.AskForSigShare:
			if len(msg.Data) != 2 || keyShare == nil || keyMeta == nil || string(msg.Data[0]) != testKeyID {
				resp.Error = message.NotInitializedError
				break
			}
			// doc is already binary!
			doc := msg.Data[1]
			// Sign
			sigShare, err := keyShare.Sign(doc, crypto.SHA256, keyMeta)
			if err != nil {
				resp.Error = message.DocSignError
				break
			}
			sigShareBytes, err := message.EncodeSigShare(sigShare)
			if err != nil {
				resp.Error = message.SigShareEncodeError
				break
			}
			resp.AddMessage(sigShareBytes)
		default:
			resp.Error = message.UnknownError
		}
		if resp.Error != message.Ok {
			t.Errorf(resp.Error.Error())
		}
		_, err = out.SendMessage(resp.GetBytesLists()...)
		if err != nil {
			resp.Error = message.SendResponseError
			t.Errorf(resp.Error.ComposeError(err))
		}
		// In this mock up, we stop the server after signing and sending successfully
		if resp.Error == message.Ok && resp.Type == message.AskForSigShare {
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
			ip:      testIP,
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
		Host:    testIP,
		Port:    initPort,
		Nodes:   make([]*NodeConfig, numNodes),
		Timeout: testTimeout,
	}
	initPort++
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
			Host:      stub.ip,
			Port:      stub.port,
			PublicKey: stub.pubKey,
		}
	}
	return
}

func createConnection() (conn *Server, nodes []*NodeStub, err error) {

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
	// We add our pub key
	zmq4.AuthCurveAdd("*", conn.pubKey)
	zmq4.AuthAllow(conn.host.String())

	// and open the connection
	defer conn.Close()
	if err != nil {
		t.Errorf("cannot close connection: %v", err)
		return
	}

	// We start the client nodes and add their Host and keys
	for i := 0; i < len(nodes); i++ {
		node := nodes[i]
		zmq4.AuthAllow(TchsmDomain, node.ip)
		zmq4.AuthCurveAdd(TchsmDomain, conn.pubKey)
		go func() {
			err := node.StartAndWait(conn, t)
			if err != nil {
				t.Errorf("%v", err)
			}
		}()
	}
	time.Sleep(3 * time.Second)
	// Sending keys

	// Extracted from libtdc documentation
	keyShares, keyMeta, err := tcrsa.NewKey(512, uint16(testK), uint16(testL), nil)
	if err != nil {
		t.Errorf("cannot create keys: %v", err)
		return
	}

	if err := conn.SendKeyShares(testKeyID, keyShares, keyMeta); err != nil {
		t.Errorf("cannot send key shares: %v", err)
		return
	}

	// Receiving acks
	if err := conn.AckKeyShares(); err != nil {
		t.Errorf("error acking key shares: %v", err)
		return
	}

	// Hashing a doc (hello world)
	docHash := sha256.Sum256([]byte("hello world"))

	// PKCS1 Padding

	docPKCS1, err := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		t.Errorf("error preparing hash: %v", err)
		return
	}

	// Asking for signatures
	if err := conn.AskForSigShares(testKeyID, docPKCS1); err != nil {
		t.Errorf("error asking for sigshares: %v", err)
		return
	}

	// Retrieving signatures
	sigShares, err := conn.GetSigShares()
	if err != nil {
		t.Errorf("error retrieving sigshares: %v", err)
		return
	}

	if len(sigShares) < testK {
		t.Errorf("there are no enough sigshares")
		return
	}
	// Finally we join them.
	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
		return
	}

	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		t.Errorf(fmt.Sprintf("%v\n", err))
		return
	}

}
