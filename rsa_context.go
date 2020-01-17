package main

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcrsa"
	"io"
	"reflect"
)

type RSASignContext struct {
	dtc         *DTC
	randSrc     io.Reader
	keyMeta     *tcrsa.KeyMeta // Key Metainfo used in signing.
	mechanism   *Mechanism     // Mechanism used to sign in a Sign session.
	keyID       string         // Key ID used in signing.
	data        []byte         // Data to sign.
	initialized bool           // // True if the user executed a Sign method and it has not finished yet.
}

type RSAVerifyContext struct {
	dtc         *DTC
	randSrc     io.Reader
	keyMeta     *tcrsa.KeyMeta // Key Metainfo used in sign verification.
	mechanism   *Mechanism     // Mechanism used to verify a signature in a Verify session.
	keyID       string         // Key ID used in sign verification.
	data        []byte         // Data to verify.
	initialized bool           // True if the user executed a Verify method and it has not finished yet.
}

func (context *RSASignContext) Initialized() bool {
	return context.initialized
}

func (context *RSASignContext) Init(metaBytes []byte) (err error) {
	context.keyMeta, err = message.DecodeRSAKeyMeta(metaBytes)
	context.initialized = true
	return
}

func (context *RSASignContext) Length() int {
	return C.ulong(context.keyMeta.PublicKey.Size())
}

func (context *RSASignContext) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *RSASignContext) Final() ([]byte, error) {
	prepared, err := context.mechanism.Prepare(
		context.randSrc,
		context.keyMeta.PublicKey.Size(),
		context.data,
	)
	if err != nil {
		return nil, err
	}
	sign, err := context.dtc.RSASignData(context.keyID, context.keyMeta, prepared)
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

func (context *RSAVerifyContext) Initialized() bool {
	return context.initialized
}

func (context *RSAVerifyContext) Init(metaBytes []byte) (err error) {
	context.keyMeta, err = message.DecodeRSAKeyMeta(metaBytes)
	context.initialized = true
	return
}

func (context *RSAVerifyContext) Length() int {
	return C.ulong(context.keyMeta.PublicKey.Size())
}

func (context *RSAVerifyContext) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *RSAVerifyContext) Final(signature []byte) error {
	return context.mechanism.Verify(
		context.keyMeta.PublicKey,
		context.data,
		signature,
	)
}

func createRSAPublicKey(keyID string, pkAttrs Attributes, keyMeta *tcrsa.KeyMeta) (Attributes, error) {

	eBytes := make([]byte, reflect.TypeOf(keyMeta.PublicKey.E).Size())
	binary.LittleEndian.PutUint64(eBytes, uint64(keyMeta.PublicKey.E))

	pubKeyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(pubKeyBytes, C.CKO_PUBLIC_KEY)

	encodedKeyMeta, err := message.EncodeRSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createRSAPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	// This fields are defined in SoftHSM implementation
	pkAttrs.SetIfUndefined(
		&Attribute{C.CKA_CLASS, pubKeyBytes},
		&Attribute{C.CKA_KEY_TYPE, []byte{C.CKK_RSA}},
		&Attribute{C.CKA_KEY_GEN_MECHANISM, []byte{C.CKM_RSA_PKCS_KEY_PAIR_GEN}},
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
		&Attribute{C.CKA_MODULUS_BITS, nil},
	)

	pkAttrs.Set(
		// E and N from PK
		&Attribute{C.CKA_MODULUS, keyMeta.PublicKey.N.Bytes()},
		&Attribute{C.CKA_PUBLIC_EXPONENT, eBytes},

		// Custom Fields
		&Attribute{AttrTypeKeyHandler, []byte(keyID)},
		&Attribute{AttrTypeKeyMeta, encodedKeyMeta},
	)

	return pkAttrs, nil
}

func createRSAPrivateKey(keyID string, skAttrs Attributes, keyMeta *tcrsa.KeyMeta) (Attributes, error) {

	eBytes := make([]byte, reflect.TypeOf(keyMeta.PublicKey.E).Size())
	binary.LittleEndian.PutUint64(eBytes, uint64(keyMeta.PublicKey.E))

	privKeyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(privKeyBytes, C.CKO_PRIVATE_KEY)

	encodedKeyMeta, err := message.EncodeRSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createRSAPrivateKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	// This fields are defined in SoftHSM implementation
	skAttrs.SetIfUndefined(
		&Attribute{C.CKA_CLASS, privKeyBytes},
		&Attribute{C.CKA_KEY_TYPE, []byte{C.CKK_RSA}},
		&Attribute{C.CKA_KEY_GEN_MECHANISM, []byte{C.CKM_RSA_PKCS_KEY_PAIR_GEN}},
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
		// E and N from PK
		&Attribute{C.CKA_MODULUS, keyMeta.PublicKey.N.Bytes()},
		&Attribute{C.CKA_PUBLIC_EXPONENT, eBytes},

		// Custom Fields
		&Attribute{AttrTypeKeyHandler, []byte(keyID)},
		&Attribute{AttrTypeKeyMeta, encodedKeyMeta},
	)

	return skAttrs, nil
}
