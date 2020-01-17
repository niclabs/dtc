package main

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcecdsa"
	"io"
)

type ECDSASignContext struct {
	dtc         *DTC
	randSrc     io.Reader
	keyMeta     *tcecdsa.KeyMeta // Key Metainfo used in signing.
	pubKey      *ecdsa.PublicKey // Public Key used in signing.
	mechanism   *Mechanism       // Mechanism used to sign in a Sign session.
	keyID       string           // Key ID used in signing.
	data        []byte           // Data to sign.
	initialized bool             // // True if the user executed a Sign method and it has not finished yet.
}

type ECDSAVerifyContext struct {
	dtc         *DTC
	randSrc     io.Reader
	keyMeta     *tcecdsa.KeyMeta // Key Metainfo used in sign verification.
	pubKey      *ecdsa.PublicKey // Public Key used in signing verification.
	mechanism   *Mechanism       // Mechanism used to verify a signature in a Verify session.
	keyID       string           // Key ID used in sign verification.
	data        []byte           // Data to verify.
	initialized bool             // True if the user executed a Verify method and it has not finished yet.
}

func (context *ECDSASignContext) Initialized() bool {
	return context.initialized
}

func (context *ECDSASignContext) Init(metaBytes []byte) (err error) {
	context.keyMeta, err = message.DecodeECDSAKeyMeta(metaBytes)
	context.initialized = true
	return
}

func (context *ECDSASignContext) Length() int {
	return (context.pubKey.Params().BitSize + 7)/8
}

func (context *ECDSASignContext) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *ECDSASignContext) Final() ([]byte, error) {
	prepared, err := context.mechanism.Prepare(
		context.randSrc,
		context.Length(),
		context.data,
	)
	if err != nil {
		return nil, err
	}
	r, s, err := context.dtc.ECDSASignData(context.keyID, context.keyMeta, prepared)
	if err != nil {
		return nil, err
	}
	if err = context.mechanism.Verify(
		context.keyMeta.PublicKey,
		context.data,
		sign,
	); err != nil {
		return nil, err
	}
	return sign, nil
}

func (context *ECDSAVerifyContext) Initialized() bool {
	return context.initialized
}

func (context *ECDSAVerifyContext) Init(metaBytes []byte) (err error) {
	context.keyMeta, err = message.DecodeECDSAKeyMeta(metaBytes)
	context.initialized = true
	return
}

func (context *ECDSAVerifyContext) Length() int {
	return (context.pubKey.Params().BitSize + 7)/8
}

func (context *ECDSAVerifyContext) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *ECDSAVerifyContext) Final(signature []byte) error {
	return context.mechanism.Verify(
		context.pubKey,
		context.data,
		signature,
	)
}

func createECDSAPublicKey(keyID string, pkAttrs Attributes, pk *ecdsa.PublicKey, keyMeta *tcecdsa.KeyMeta) (Attributes, error) {

	encodedKeyMeta, err := message.EncodeECDSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createECDSAPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	ecPointSerialized, err := pubKeyToASN1(pk)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(pubKeyBytes, C.CKO_PUBLIC_KEY)

	// This fields are defined in SoftHSM implementation
	pkAttrs.SetIfUndefined(
		&Attribute{C.CKA_CLASS, pubKeyBytes},
		&Attribute{C.CKA_KEY_TYPE, []byte{C.CKK_EC}},
		&Attribute{C.CKA_KEY_GEN_MECHANISM, []byte{C.CKM_EC_KEY_PAIR_GEN}},
		&Attribute{C.CKA_LOCAL, []byte{C.CK_TRUE}},

		// This fields are our defaults
		&Attribute{C.CKA_LABEL, nil},
		&Attribute{C.CKA_ID, nil},
		&Attribute{C.CKA_SUBJECT, nil},
		&Attribute{C.CKA_PRIVATE, []byte{C.CK_FALSE}},
		&Attribute{C.CKA_MODIFIABLE, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_TOKEN, []byte{C.CK_FALSE}},
		&Attribute{C.CKA_DERIVE, []byte{C.CK_FALSE}},
		&Attribute{C.CKA_ENCRYPT, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_VERIFY, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_VERIFY_RECOVER, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_WRAP, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_TRUSTED, []byte{C.CK_FALSE}},
		&Attribute{C.CKA_START_DATE, make([]byte, 8)},
		&Attribute{C.CKA_END_DATE, make([]byte, 8)},
	)

	pkAttrs.Set(
		// ECDSA Public Key
		&Attribute{C.CKA_EC_POINT, ecPointSerialized},

		// Custom fields
		&Attribute{AttrTypeKeyHandler, []byte(keyID)},
		&Attribute{AttrTypeKeyMeta, encodedKeyMeta},
	)

	return pkAttrs, nil
}

func createECDSAPrivateKey(keyID string, skAttrs Attributes, pk *ecdsa.PublicKey, keyMeta *tcecdsa.KeyMeta) (Attributes, error) {

	encodedKeyMeta, err := message.EncodeECDSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createECDSAPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	ecPointSerialized, err := pubKeyToASN1(pk)
	if err != nil {
		return nil, err
	}

	privKeyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(privKeyBytes, C.CKO_PRIVATE_KEY)

	// This fields are defined in SoftHSM implementation
	skAttrs.SetIfUndefined(
		&Attribute{C.CKA_CLASS, privKeyBytes},
		&Attribute{C.CKA_KEY_TYPE, []byte{C.CKK_EC}},
		&Attribute{C.CKA_KEY_GEN_MECHANISM, []byte{C.CKM_EC_KEY_PAIR_GEN}},
		&Attribute{C.CKA_LOCAL, []byte{C.CK_TRUE}},

		// This fields are our defaults
		&Attribute{C.CKA_LABEL, nil},
		&Attribute{C.CKA_ID, nil},
		&Attribute{C.CKA_SUBJECT, nil},
		&Attribute{C.CKA_PRIVATE, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_MODIFIABLE, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_TOKEN, []byte{C.CK_FALSE}},
		&Attribute{C.CKA_DERIVE, []byte{C.CK_FALSE}},

		&Attribute{C.CKA_WRAP_WITH_TRUSTED, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_ALWAYS_AUTHENTICATE, []byte{C.CK_FALSE}},
		&Attribute{C.CKA_SENSITIVE, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_ALWAYS_SENSITIVE, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_DECRYPT, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_SIGN, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_SIGN_RECOVER, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_UNWRAP, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_EXTRACTABLE, []byte{C.CK_FALSE}},
		&Attribute{C.CKA_NEVER_EXTRACTABLE, []byte{C.CK_TRUE}},
		&Attribute{C.CKA_START_DATE, make([]byte, 8)},
		&Attribute{C.CKA_END_DATE, make([]byte, 8)},

	)
	skAttrs.Set(
		// ECDSA Public Key
		&Attribute{C.CKA_EC_POINT, ecPointSerialized},
		// Custom Fields
		&Attribute{AttrTypeKeyHandler, []byte(keyID)},
		&Attribute{AttrTypeKeyMeta, encodedKeyMeta},
	)

	return skAttrs, nil
}

var curveNameToCurve = map[string]elliptic.Curve{
	"P-224": elliptic.P224(),
	"P-256": elliptic.P256(),
	"P-384": elliptic.P384(),
	"P-521": elliptic.P521(),
}

// from github.com/Thalesignite/crypto11
var curveNameToASN1 = map[string]asn1.ObjectIdentifier{
	"P-224": {1, 3, 132, 0, 33},
	"P-256": {1, 2, 840, 10045, 3, 1, 7},
	"P-384": {1, 3, 132, 0, 34},
	"P-521": {1, 3, 132, 0, 35},
}

func asn1ToCurveName(b []byte) (string, error) {
	var v asn1.ObjectIdentifier
	extra, err := asn1.Unmarshal(b, v)
	if len(extra) > 0 {
		return "", NewError("Session.GenerateKeyPair", "extra data in params", C.CKR_DOMAIN_PARAMS_INVALID)
	}
	if err != nil {
		return "", NewError("Session.GenerateKeyPair", fmt.Sprintf("error decrypting params: %s", err), C.CKR_DOMAIN_PARAMS_INVALID)
	}
	for name, item := range curveNameToASN1 {
		if v.Equal(item) {
			return name, nil
		}
	}
	return "", NewError("Session.GenerateKeyPair", "curve unsupported", C.CKR_CURVE_NOT_SUPPORTED)
}

func pubKeyToASN1(pk *ecdsa.PublicKey) ([]byte, error) {
	ecPointBytes := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
	ecPointASN1, err := asn1.Marshal(ecPointBytes)
	if err != nil {
		return nil, NewError("pubKeyToASN1", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}
	return ecPointASN1, nil
}

func asn1ToPublicKey(c elliptic.Curve, b []byte) (*ecdsa.PublicKey, error) {
	var pointBytes []byte
	ecPointASN1, err := asn1.Unmarshal(b, pointBytes)
	if err != nil {
		return nil, NewError("asn1ToPubKey", fmt.Sprintf("error decoding ec pubkey: %s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}
	x, y := elliptic.Unmarshal(c, ecPointASN1)
	if x == nil {
		return nil, NewError("asn1ToPubKey", "error decoding ec pubkey: cannot transform the binary value into a point", C.CKR_ARGUMENTS_BAD)

	}
	return &ecdsa.PublicKey{
		Curve: c,
		X:     x,
		Y:     y,
	}, nil
}
