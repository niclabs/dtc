package objects


/**
#include "../criptoki/pkcs11go.h"
 */
import "C"
import (
	"crypto"
	"crypto/rsa"
	"io"
	"unsafe"
)

type Mechanism struct {
	Type      CMechanismType
	Parameter []byte
}

func CToMechanism(pMechanism CMechanismPtr) *Mechanism {
	cMechanism := (*CMechanism)(unsafe.Pointer(pMechanism))
	mechanismType := cMechanism._type
	mechanismVal := C.GoStringN(unsafe.Pointer(cMechanism.pValue), C.int(cMechanism.ulValueLen))
	return &CMechanism{
		Type:  mechanismType,
		Value: mechanismVal,
	}

}

func (mechanism *Mechanism) ToC(cDst CMechanismPtr) error {
	cMechanism := (*CMechanism)(unsafe.Pointer(cDst))
	if cMechanism.ulValueLen >= len(mechanism.Parameter) {
		cMechanism._type = mechanism.Type
		cMechanism.ulValueLen = C.int(len(mechanism.Parameter))
		cParameter := C.CBytes(mechanism.Parameter)
		defer C.free(unsafe.Pointer(cParameter))
		C.memcpy(cMechanism.pValue, cParameter, cMechanism.ulValueLen)
	} else {
		return NewError("Mechanism.ToC", "Buffer too small", C.CKR_BUFFER_TOO_SMALL)
	}
	return nil
}

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

func (mechanism *Mechanism) Prepare(randSrc io.Reader, nBits int, data []byte) (prepared []byte, err error) {
	hashType, err := mechanism.GetHashType()
	if err != nil {
		return
	}
	switch mechanism.Type {
	case C.CKM_RSA_PKCS, C.CKM_MD5_RSA_PKCS, C.CKM_SHA1_RSA_PKCS, C.CKM_SHA256_RSA_PKCS, C.CKM_SHA384_RSA_PKCS, C.CKM_SHA512_RSA_PKCS:
		hashFunc := hashType.New()
		hash := hashFunc.Sum(data)
		return padPKCS1v15(hashType, nBits, hash)
	case C.CKM_SHA1_RSA_PKCS_PSS, C.CKM_SHA256_RSA_PKCS_PSS, C.CKM_SHA384_RSA_PKCS_PSS, C.CKM_SHA512_RSA_PKCS_PSS:
		if hashType < crypto.Hash(0) {
			err = NewError("Mechanism.Sign", "mechanism hash type is not supported with PSS padding", C.CKR_MECHANISM_INVALID)
		}
		hashFunc := hashType.New()
		hash := hashFunc.Sum(data)
		return padPSS(randSrc, hashType, nBits, hash)
	default:
		err = NewError("Mechanism.Sign", "mechanism not supported yet for preparing", C.CKR_MECHANISM_INVALID)
		return
	}
}

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
