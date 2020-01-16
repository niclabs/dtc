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
	"github.com/google/uuid"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcecdsa"
)

type ECDSASession struct {
	signKeyMeta   *tcecdsa.KeyMeta // Key Metainfo used in signing
	verifyKeyMeta *tcecdsa.KeyMeta // Key Metainfo used in sign verification
}

func (session *Session) generateECDSAKeyPair(pkTemplate, skTemplate Attributes) (pkObject, skObject *CryptoObject, err error) {
	var dtc *DTC
	dtc, err = session.GetDTC()
	if err != nil {
		return
	}
	keyID := uuid.New().String()

	// TODO: ECDSA
	curveParams, err := pkTemplate.GetAttributeByType(C.CKA_EC_PARAMS)
	if err != nil {
		err = NewError("Session.GenerateECDSAKeyPair", "curve not defined", C.CKR_TEMPLATE_INCOMPLETE)

	}
	curveName, err := asn1ToCurveName(curveParams.Value)
	if err != nil {
		return
	}
	curve, ok := curveNameToCurve[curveName]
	if !ok {
		err = NewError("Session.GenerateECDSAKeyPair", "curve not supported", C.CKR_CURVE_NOT_SUPPORTED)
		return
	}
	keyMeta, ecPK, err := dtc.ECDSACreateKey(keyID, curve)
	if err != nil {
		return
	}
	pk, err := createECDSAPublicKey(keyID, pkTemplate, ecPK, keyMeta)
	if err != nil {
		return
	}
	pkObject, err = session.CreateObject(pk)
	if err != nil {
		return
	}
	sk, err := createECDSAPrivateKey(keyID, skTemplate, ecPK, keyMeta)
	if err != nil {
		return
	}
	skObject, err = session.CreateObject(sk)
	if err != nil {
		return
	}
	return
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
		return nil, NewError("Session.createECDSAPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}
	return ecPointASN1, nil
}
