package main

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"crypto"
	"crypto/rsa"
	"io"
	"unsafe"
)

// Mechanism represents a cryptographic operation that the HSM supports.
type Mechanism struct {
	Type      C.CK_MECHANISM_TYPE // Mechanism Type
	Parameter []byte // Parameters for the mechanism
}

// CToMechanism transforms a C mechanism into a Mechanism Golang structure.
func CToMechanism(pMechanism C.CK_MECHANISM_PTR) *Mechanism {
	cMechanism := (*C.CK_MECHANISM)(unsafe.Pointer(pMechanism))
	mechanismType := cMechanism.mechanism
	mechanismVal := C.GoBytes(unsafe.Pointer(cMechanism.pParameter), C.int(cMechanism.ulParameterLen))
	return &Mechanism{
		Type:      mechanismType,
		Parameter: mechanismVal,
	}

}

// ToC transforms a Mechanism Golang Structure into a C structure.
func (mechanism *Mechanism) ToC(cDst C.CK_MECHANISM_PTR) error {
	cMechanism := (*C.CK_MECHANISM)(unsafe.Pointer(cDst))
	if cMechanism.ulParameterLen >= C.CK_ULONG(len(mechanism.Parameter)) {
		cMechanism.mechanism = mechanism.Type
		cMechanism.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
		cParameter := C.CBytes(mechanism.Parameter)
		defer C.free(unsafe.Pointer(cParameter))
		C.memcpy(unsafe.Pointer(cMechanism.pParameter), cParameter, cMechanism.ulParameterLen)
	} else {
		return NewError("Mechanism.ToC", "Buffer too small", C.CKR_BUFFER_TOO_SMALL)
	}
	return nil
}

// GetHashType returns the crypto.Hash object related to the mechanism type of the receiver.
func (mechanism *Mechanism) GetHashType() (h crypto.Hash, err error) {
	switch mechanism.Type {
	case C.CKM_RSA_PKCS:
		return crypto.Hash(0), nil
	case C.CKM_MD5_RSA_PKCS, C.CKM_MD5:
		h = crypto.MD5
	case C.CKM_SHA1_RSA_PKCS_PSS, C.CKM_SHA1_RSA_PKCS, C.CKM_SHA_1:
		h = crypto.SHA1
	case C.CKM_SHA256_RSA_PKCS_PSS, C.CKM_SHA256_RSA_PKCS, C.CKM_SHA256:
		h = crypto.SHA256
	case C.CKM_SHA384_RSA_PKCS_PSS, C.CKM_SHA384_RSA_PKCS, C.CKM_SHA384:
		h = crypto.SHA384
	case C.CKM_SHA512_RSA_PKCS_PSS, C.CKM_SHA512_RSA_PKCS, C.CKM_SHA512:
		h = crypto.SHA512
	default:
		err = NewError("Mechanism.Sign", "mechanism not supported yet for hashing", C.CKR_MECHANISM_INVALID)
		return
	}
	return
}

// Prepare hashes the data to sign using the mechanism method. It also receives a random source, that is used in PSS padding mechanism.
func (mechanism *Mechanism) Prepare(randSrc io.Reader, nBits int, data []byte) (prepared []byte, err error) {
	hashType, err := mechanism.GetHashType()
	var hash []byte
	if err != nil {
		return
	}
	switch mechanism.Type {
	case C.CKM_RSA_PKCS, C.CKM_MD5_RSA_PKCS, C.CKM_SHA1_RSA_PKCS, C.CKM_SHA256_RSA_PKCS, C.CKM_SHA384_RSA_PKCS, C.CKM_SHA512_RSA_PKCS:
		if hashType == crypto.Hash(0) {
			hash = data
		} else {
			hashFunc := hashType.New()
			_, err = hashFunc.Write(data)
			if err != nil {
				return
			}
			hash = hashFunc.Sum(nil)
		}
		return padPKCS1v15(hashType, nBits, hash)
	case C.CKM_SHA1_RSA_PKCS_PSS, C.CKM_SHA256_RSA_PKCS_PSS, C.CKM_SHA384_RSA_PKCS_PSS, C.CKM_SHA512_RSA_PKCS_PSS:
		if hashType < crypto.Hash(0) {
			err = NewError("Mechanism.Sign", "mechanism hash type is not supported with PSS padding", C.CKR_MECHANISM_INVALID)
		}
		hashFunc := hashType.New()
		_, err = hashFunc.Write(data)
		if err != nil {
			return
		}
		hash = hashFunc.Sum(nil)
		return padPSS(randSrc, hashType, nBits, hash)
	default:
		err = NewError("Mechanism.Sign", "mechanism not supported yet for preparing", C.CKR_MECHANISM_INVALID)
		return
	}
}

// Verify verifies that a signature is coherent with the data that it signs, using the public key.
func (mechanism *Mechanism) Verify(pubKey crypto.PublicKey, data []byte, signature []byte) (err error) {
	hashType, err := mechanism.GetHashType()
	if err != nil {
		return
	}
	switch mechanism.Type {
	case C.CKM_RSA_PKCS, C.CKM_MD5_RSA_PKCS, C.CKM_SHA1_RSA_PKCS, C.CKM_SHA256_RSA_PKCS, C.CKM_SHA384_RSA_PKCS, C.CKM_SHA512_RSA_PKCS:
		return rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), hashType, data, signature)
	case C.CKM_SHA1_RSA_PKCS_PSS, C.CKM_SHA256_RSA_PKCS_PSS, C.CKM_SHA384_RSA_PKCS_PSS, C.CKM_SHA512_RSA_PKCS_PSS:
		if hashType < crypto.Hash(0) {
			err = NewError("Mechanism.Sign", "mechanism hash type is not supported with PSS padding", C.CKR_MECHANISM_INVALID)
		}
		return rsa.VerifyPSS(pubKey.(*rsa.PublicKey), hashType, data, signature, &rsa.PSSOptions{})
	default:
		err = NewError("Mechanism.Sign", "mechanism not supported yet for preparing", C.CKR_MECHANISM_INVALID)
		return
	}
}
