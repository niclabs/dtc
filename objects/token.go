package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"strings"
	"sync"
	"time"
	"unsafe"
)

// Security level constant
type SecurityLevel int

const (
	Error SecurityLevel = iota
	SecurityOfficer
	User
	Public
)

// A token of the PKCS11 device.
type Token struct {
	sync.Mutex
	Label         string
	Pin           string
	SoPin         string
	Objects       CryptoObjects
	tokenFlags    uint64
	securityLevel SecurityLevel
	loggedIn      bool
	slot          *Slot
}

func NewToken(slot *Slot, label, userPin, soPin string) (*Token, error) {
	if len(label) > 32 {
		return nil, NewError("objects.NewToken", "Label with more than 32 chars", C.CKR_ARGUMENTS_BAD)
	}
	newToken := &Token{
		Label: label,
		Pin:   userPin,
		SoPin: soPin,
		tokenFlags: C.CKF_RNG |
			C.CKF_WRITE_PROTECTED |
			C.CKF_LOGIN_REQUIRED |
			C.CKF_USER_PIN_INITIALIZED |
			C.CKF_TOKEN_INITIALIZED,
		slot: slot,
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
		return NewError("token.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (C.CK_TOKEN_INFO_PTR)(unsafe.Pointer(pInfo))

	if len(token.Label) == 0 {
		C.memset(info.label, " ", 32)
	} else {
		cLabel := C.Cstring(token.Label)
		defer C.free(unsafe.Pointer(cLabel))
		C.memset(info.label, cLabel, len(token.Label))
	}

	if token.slot == nil {
		return NewError("token.GetInfo", "cannot get info: token is not bound to a slot", C.CKR_ARGUMENTS_BAD)
	}

	manufacturerID := token.slot.Application.Config.Criptoki.ManufacturerID
	if len(manufacturerID) > 32 {
		manufacturerID = manufacturerID[:32]
	}
	manufacturerID += strings.Repeat(" ", 32-len(manufacturerID))
	cManufacturerID := C.CString(manufacturerID)
	defer C.free(unsafe.Pointer(cManufacturerID))
	C.strncpy(info.manufacturerID, cManufacturerID, 32)

	model := token.slot.Application.Config.Criptoki.Model
	if len(model) > 16 {
		model = model[:16]
	}
	model += strings.Repeat(" ", 16-len(manufacturerID))
	cModel := C.CString(model)
	defer C.free(unsafe.Pointer(cModel))
	C.strncpy(info.model, cModel, 16)

	serialNumber := "1"
	serialNumber += strings.Repeat(" ", 16-len(manufacturerID))
	cSerialNumber := C.CString(serialNumber)
	defer C.free(unsafe.Pointer(cSerialNumber))
	C.strncpy(info.serialNumber, cSerialNumber, 16)

	info.flags = token.tokenFlags
	info.ulMaxSessionCount = token.slot.Application.Config.Criptoki.MaxSessionCount
	info.ulSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxRwSessionCount = token.slot.Application.Config.Criptoki.MaxSessionCount
	info.ulRwSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxPinLen = token.slot.Application.Config.Criptoki.MaxPinLength
	info.ulMinPinLen = token.slot.Application.Config.Criptoki.MinPinLength
	info.ulTotalPublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulTotalPrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.hardwareVersion.major = token.slot.Application.Config.Criptoki.VersionMajor
	info.hardwareVersion.minor = token.slot.Application.Config.Criptoki.VersionMinor
	info.firmwareVersion.major = token.slot.Application.Config.Criptoki.VersionMajor
	info.firmwareVersion.minor = token.slot.Application.Config.Criptoki.VersionMinor

	now := time.Now()
	cTimeStr := C.CString(now.Format("20060102150405") + "00")
	defer C.free(unsafe.Pointer(cTimeStr))
	C.memcpy(info.utcTime, cTimeStr, 16)

	return nil
}

// Sets the user pin to a new pin.
func (token *Token) SetUserPin(pin string) {
	token.Pin = pin
}

// It always returns true
func (token *Token) IsInited() bool {
	return true
}

// Gets security level set for the token at Login
func (token *Token) GetSecurityLevel() SecurityLevel {
	return token.securityLevel
}

// Checks if the pin provided is the user pin
func (token *Token) CheckUserPin(pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) (SecurityLevel, error) {
	pin := C.GoStringN(pPin, ulPinLen)
	if token.Pin == pin {
		return User, nil
	} else {
		return Error, NewError("token.GetUserPin", "incorrect pin", C.CKR_PIN_INCORRECT)
	}
}

// Checks if the pin provided is the SO pin.
func (token *Token) CheckSecurityOfficerPin(pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) (SecurityLevel, error) {
	pin := C.GoStringN(pPin, ulPinLen)
	if token.SoPin == pin {
		return User, nil
	} else {
		return Error, NewError("token.GetUserPin", "incorrect pin", C.CKR_PIN_INCORRECT)
	}
}

// Logs into the token, or returns an error if something goes wrong.
func (token *Token) Login(userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) error {
	if token.loggedIn &&
		(userType == C.CKU_USER && token.securityLevel == SecurityOfficer) ||
		(userType == C.CKU_SO && token.securityLevel == User) {
		return NewError("token.Login", "another user already logged in", C.CKR_ANOTHER_USER_ALREADY_LOGGED_IN)
	}

	if pPin == nil {
		return NewError("token.Login", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	switch userType {
	case C.CKU_SO:
		securityLevel, err := token.CheckSecurityOfficerPin(pPin, ulPinLen)
		if err != nil {
			return err
		}
		token.securityLevel = securityLevel
	case C.CKU_USER:
		securityLevel, err := token.CheckUserPin(pPin, ulPinLen)
		if err != nil {
			return err
		}
		token.securityLevel = securityLevel
	case C.CKU_CONTEXT_SPECIFIC:
		switch token.securityLevel {
		case Public:
			return NewError("token.Login", "Bad userType", C.CKR_OPERATION_NOT_INITIALIZED)
		case User:
			securityLevel, err := token.CheckUserPin(pPin, ulPinLen)
			if err != nil {
				return err
			}
			token.securityLevel = securityLevel
		case SecurityOfficer:
			securityLevel, err := token.CheckSecurityOfficerPin(pPin, ulPinLen)
			if err != nil {
				return err
			}
			token.securityLevel = securityLevel

		}
	default:
		return NewError("token.Login", "Bad userType", C.CKR_USER_TYPE_INVALID)
	}
	token.loggedIn = true
	return nil
}

// Logs out from the token.
func (token *Token) Logout() {
	token.securityLevel = Public
	token.loggedIn = false
}

// Adds a cryptoObject to the token
func (token *Token) AddObject(object *CryptoObject) {
	handle := object.Handle
	// TODO: mutex?
	token.Objects[handle] = object
}

// Returns the label of the token (should remove. Label is a public property!
func (token *Token) GetLabel() string {
	return token.Label
}

// Returns an object that uses the handle provided.
func (token *Token) GetObject(handle CCryptoObjectHandle) (*CryptoObject, error) {
	token.Lock()
	defer token.Unlock()
	for _, object := range token.Objects {
		if object.Handle == handle {
			return object, nil
		}
	}
	return nil, NewError("Session.DestroyObject", "object not found", C.CKR_OBJECT_HANDLE_INVALID)
}

func (token *Token) DeleteObject(handle CCryptoObjectHandle) error {
	token.Lock()
	defer token.Unlock()
	objPos := -1
	for i, object := range token.Objects {
		if object.Handle == handle {
			objPos = i
			break
		}
	}
	if objPos == -1 {
		return NewError("Session.DestroyObject", "object not found", C.CKR_OBJECT_HANDLE_INVALID)
	}
	token.Objects = append(token.Objects[:objPos], token.Objects[objPos+1:]...)
	return nil
}

// Copies the state of a token
func (token *Token) CopyState(token2 *Token) {
	token.Pin = token2.Pin
	token.securityLevel = token2.securityLevel
	token.loggedIn = token2.loggedIn
	token.SoPin = token2.SoPin
}
