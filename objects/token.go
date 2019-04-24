package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import "unsafe"

// A token of the PKCS11 device.
type Token struct {
	Label   string
	Pin     string
	SoPin   string
	Objects CryptoObjects
	tokenFlags C.CK_FLAGS
	securityLevel SecurityLevel
}

func NewToken(label, userpin, soPin string) (*Token, error) {
	if len(label) > 32 {
		return nil, NewError("objects.NewToken","Label with more than 32 chars", C.CKR_ARGUMENTS_BAD)
	}
	newToken := &Token{
		Label: label,
		Pin: userpin,
		SoPin: soPin,
		tokenFlags: C.CKF_RNG |
			C.CKF_WRITE_PROTECTED |
			C.CKF_LOGIN_REQUIRED |
			C.CKF_USER_PIN_INITIALIZED |
			C.CKF_TOKEN_INITIALIZED,
	}
	return newToken, nil
}

// Equals returns true if the token objects are equal.
func (token *Token) Equals(token2 *Token) bool {
	return token.Label == token2.Label &&
		token.Pin == token2.Pin &&
		token.SoPin == token2.SoPin &&
		token.Objects.Equals(token2.Objects)
}


func (token *Token) GetInfo(pInfo C.CK_TOKEN_INFO_PTR) error {
	if pInfo == nil {
		return NewError("Token.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_TOKEN_INFO)(unsafe.Pointer(pInfo))
	info.manufacturerID.

	return nil
}