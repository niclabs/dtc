package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/niclabs/tcecdsa"
	"log"
)

// ECDSACreateKey creates a new key and saves its shares distributed among all the nodes.
func (dtc *DTC) ECDSACreateKey(keyID string, curve elliptic.Curve) (*tcecdsa.KeyMeta, *ecdsa.PublicKey, error) {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Creating new key with curve=%s, threshold=%d and nodes=%d", curve.Params().Name, dtc.Threshold, dtc.Nodes)
	keyShares, keyMeta, err := tcecdsa.NewKey(uint8(dtc.Threshold), uint8(dtc.Nodes), curve, rand.Reader, nil)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Sending key shares with keyid=%s", keyID)
	if err := dtc.Connection.SendECDSAKeyShares(keyID, keyShares, keyMeta); err != nil {
		return nil, nil, err
	}
	log.Printf("Acking key shares related to keyid=%s", keyID)
	keyInitMessageList, err := dtc.Connection.GetECDSAKeyInitMessageList()
	if err != nil {
		return nil, nil, err
	}
	pk, err := keyMeta.GetPublicKey(keyInitMessageList)
	if err != nil {
		return nil, nil, err
	}
	if err := dtc.Connection.SendECDSAKeyInitMessageList(keyID, keyInitMessageList); err != nil {
		return nil, nil, err
	}
	if err := dtc.Connection.AckECDSAKeyInitReception(); err != nil {
		return nil, nil, err
	}
	return keyMeta, pk, nil
}

// ECDSASignData with a key name a byte hash, sending it to all the keyshare holders.
func (dtc *DTC) ECDSASignData(keyID string, meta *tcecdsa.KeyMeta, data []byte) ([]byte, error) {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Signing data with key of id=%s", keyID)
	defer func() {
		// Reset Session
		dtc.Connection.AskForECDSASessionRestart()
		dtc.Connection.AckECDSASessionRestart()
	}()
	// Round 1
	if err := dtc.Connection.AskForECDSARound1MessageList(keyID, data); err != nil {
		return nil, err
	}
	nodeIDs, round1List, err := dtc.Connection.GetECDSARound1MessageList(int(meta.Paillier.K))
	if err != nil {
		return nil, err
	}

	//Round 2
	if err := dtc.Connection.AskForECDSARound2MessageList(keyID, nodeIDs, round1List); err != nil {
		return nil, err
	}
	round2List, err := dtc.Connection.GetECDSARound2MessageList(int(meta.Paillier.K))
	if err != nil {
		return nil, err
	}

	// Round 3
	if err := dtc.Connection.AskForECDSARound3MessageList(keyID, nodeIDs, round2List); err != nil {
		return nil, err
	}
	round3List, err := dtc.Connection.GetECDSARound3MessageList(int(meta.Paillier.K))
	if err != nil {
		return nil, err
	}

	// GetSignature
	if err := dtc.Connection.AskForECDSASignature(keyID, nodeIDs, round3List); err != nil {
		return nil, err
	}
	r, s, err := dtc.Connection.GetECDSASignature(int(meta.Paillier.K))
	if err != nil {
		return nil, err
	}
	// Finally we return the signature
	return tcecdsa.MarshalSignature(r, s)
}

// ECDSADeleteKey deletes the key shares of the key with id = keyID from all the nodes.
func (dtc *DTC) ECDSADeleteKey(keyID string) error {
	dtc.Lock()
	defer dtc.Unlock()
	log.Printf("Deleting key shares with keyid=%s", keyID)
	if err := dtc.Connection.AskForECDSAKeyDeletion(keyID); err != nil {
		return err
	}
	log.Printf("Acking key shares deletion related to keyid=%s", keyID)
	return dtc.Connection.AckECDSAKeyDeletion()
}
