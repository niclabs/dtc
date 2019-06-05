package message

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"github.com/niclabs/tcrsa"
)

func GetRandomHexString(len int) (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return "", err
	}
	return fmt.Sprintf("%X", b), nil
}


func EncodeKeyShare(share *tcrsa.KeyShare) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(share); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func EncodeKeyMeta(meta *tcrsa.KeyMeta) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(meta); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func EncodeSigShare(share *tcrsa.SigShare) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(share); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func DecodeKeyShare(byteShare []byte) (*tcrsa.KeyShare, error) {
	var keyShare tcrsa.KeyShare
	buffer := bytes.NewBuffer(byteShare)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&keyShare); err != nil {
		return nil, err
	}
	return &keyShare, nil
}

func DecodeKeyMeta(byteShare []byte) (*tcrsa.KeyMeta, error) {
	var keyMeta tcrsa.KeyMeta
	buffer := bytes.NewBuffer(byteShare)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&keyMeta); err != nil {
		return nil, err
	}
	return &keyMeta, nil
}


func DecodeSigShare(byteShare []byte) (*tcrsa.SigShare, error) {
	var sigShare tcrsa.SigShare
	buffer := bytes.NewBuffer(byteShare)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&sigShare); err != nil {
		return nil, err
	}
	return &sigShare, nil
}
