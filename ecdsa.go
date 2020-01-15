package main

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcecdsa"
	"github.com/niclabs/tcrsa"
	"reflect"
)

type ECDSASession struct {
	signKeyMeta     *tcecdsa.KeyMeta // Key Metainfo used in signing
	verifyKeyMeta     *tcecdsa.KeyMeta // Key Metainfo used in sign verification
}

func createECDSAPublicKey(keyID string, pkAttrs Attributes, keyMeta *tcrsa.KeyMeta) (Attributes, error) {

	// Create
	pubKeyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(pubKeyBytes, C.CKO_PUBLIC_KEY)

	// This fields are defined in SoftHSM implementation
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_CLASS, pubKeyBytes})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_KEY_TYPE, []byte{C.CKK_RSA}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_KEY_GEN_MECHANISM, []byte{C.CKM_RSA_PKCS_KEY_PAIR_GEN}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_LOCAL, []byte{C.CK_TRUE}})

	// This fields are our defaults
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_LABEL, nil})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_ID, nil})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_SUBJECT, nil})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_PRIVATE, []byte{C.CK_FALSE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_MODIFIABLE, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_TOKEN, []byte{C.CK_FALSE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_DERIVE, []byte{C.CK_FALSE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_ENCRYPT, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_VERIFY, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_VERIFY_RECOVER, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_WRAP, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_TRUSTED, []byte{C.CK_FALSE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_START_DATE, make([]byte, 8)})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_END_DATE, make([]byte, 8)})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_MODULUS_BITS, nil})

	// E and N from PK

	eBytes := make([]byte, reflect.TypeOf(keyMeta.PublicKey.E).Size())
	binary.LittleEndian.PutUint64(eBytes, uint64(keyMeta.PublicKey.E))

	pkAttrs.SetIfUndefined(&Attribute{C.CKA_MODULUS, keyMeta.PublicKey.N.Bytes()})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_PUBLIC_EXPONENT, eBytes})

	// Custom Fields

	encodedKeyMeta, err := message.EncodeRSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createRSAPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	pkAttrs.SetIfUndefined(&Attribute{AttrTypeKeyHandler, []byte(keyID)})
	pkAttrs.SetIfUndefined(&Attribute{AttrTypeKeyMeta, encodedKeyMeta})

	return pkAttrs, nil
}

func createECDSAPrivateKey(keyID string, skAttrs Attributes, keyMeta *tcrsa.KeyMeta) (Attributes, error) {

	privKeyBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(privKeyBytes, C.CKO_PRIVATE_KEY)

	// This fields are defined in SoftHSM implementation
	skAttrs.SetIfUndefined(&Attribute{C.CKA_CLASS, privKeyBytes})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_KEY_TYPE, []byte{C.CKK_RSA}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_KEY_GEN_MECHANISM, []byte{C.CKM_RSA_PKCS_KEY_PAIR_GEN}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_LOCAL, []byte{C.CK_TRUE}})

	// This fields are our defaults

	skAttrs.SetIfUndefined(&Attribute{C.CKA_LABEL, nil})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_ID, nil})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_SUBJECT, nil})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_PRIVATE, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_MODIFIABLE, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_TOKEN, []byte{C.CK_FALSE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_DERIVE, []byte{C.CK_FALSE}})

	skAttrs.SetIfUndefined(&Attribute{C.CKA_WRAP_WITH_TRUSTED, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_ALWAYS_AUTHENTICATE, []byte{C.CK_FALSE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_SENSITIVE, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_ALWAYS_SENSITIVE, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_DECRYPT, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_SIGN, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_SIGN_RECOVER, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_UNWRAP, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_EXTRACTABLE, []byte{C.CK_FALSE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_NEVER_EXTRACTABLE, []byte{C.CK_TRUE}})

	skAttrs.SetIfUndefined(&Attribute{C.CKA_START_DATE, make([]byte, 8)})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_END_DATE, make([]byte, 8)})

	// E and N from PK

	eBytes := make([]byte, reflect.TypeOf(keyMeta.PublicKey.E).Size())
	binary.LittleEndian.PutUint64(eBytes, uint64(keyMeta.PublicKey.E))

	skAttrs.SetIfUndefined(&Attribute{C.CKA_MODULUS, keyMeta.PublicKey.N.Bytes()})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_PUBLIC_EXPONENT, eBytes})

	// Custom Fields
	encodedKeyMeta, err := message.EncodeRSAKeyMeta(keyMeta)

	if err != nil {
		return nil, NewError("Session.createRSAPrivateKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	skAttrs.SetIfUndefined(&Attribute{AttrTypeKeyHandler, []byte(keyID)})
	skAttrs.SetIfUndefined(&Attribute{AttrTypeKeyMeta, encodedKeyMeta})

	return skAttrs, nil
}
