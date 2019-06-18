package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"bytes"
	"unsafe"
)

const (
	SessionObject CryptoObjectType = iota
	TokenObject
)

// A cryptoObject related to a token.
type CryptoObject struct {
	Handle     CObjectHandle
	Type       CryptoObjectType
	Attributes Attributes
}

// A map of cryptoobjects
type CryptoObjects []*CryptoObject

func CToCryptoObject(pAttributes CAttrPointer, ulCount CULong) (*CryptoObject, error) {
	attrSlice, err := CToAttributes(pAttributes, ulCount)
	if err != nil {
		return nil, err
	}
	var coType CryptoObjectType
	tokenAttr, ok := attrSlice[CToken]
	if !ok {
		return nil, NewError("CToCryptoObject", "Token attribute not found", C.CKR_ATTRIBUTE_VALUE_INVALID)
	}
	isToken := CBool(tokenAttr.Value[0])
	if isToken == CFalse {
		coType = SessionObject
	} else {
		coType = TokenObject
	}
	object := &CryptoObject{
		Type:       coType,
		Attributes: attrSlice,
	}
	return object, nil
}

// Equals returns true if the maps of crypto objects are equal.
func (objects CryptoObjects) Equals(objects2 CryptoObjects) bool {
	if len(objects) != len(objects2) {
		return false
	}
	for _, object := range objects {
		ok := false
		var object2 *CryptoObject
		for _, object2 = range objects2 {
			if object2.Handle == object.Handle {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
		if !object.Equals(object2) {
			return false
		}
	}
	return true
}

// Equals returns true if the crypto_objects are equal.
func (object *CryptoObject) Equals(object2 *CryptoObject) bool {
	return object.Handle == object2.Handle &&
		object.Attributes.Equals(object2.Attributes)
}

// https://stackoverflow.com/questions/28925179/cgo-how-to-pass-struct-array-from-c-to-go#28933938
func (object *CryptoObject) Match(attrs Attributes) bool {
	for _, theirAttr := range attrs {
		ourAttr, ok := object.Attributes[theirAttr.Type]
		if !ok || bytes.Compare(ourAttr.Value, theirAttr.Value) != 0 {
			return false
		}
	}
	return true
}

func (object *CryptoObject) FindAttribute(attrType CAttrType) *Attribute {
	if attr, ok := object.Attributes[attrType]; ok {
		return attr
	}
	return nil
}

// https://stackoverflow.com/questions/28925179/cgo-how-to-pass-struct-array-from-c-to-go#28933938
func (object *CryptoObject) CopyAttributes(pTemplate CAttrPointer, ulCount CULong) error {
	if pTemplate == nil {
		return NewError("CryptoObject.CopyAttributes", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	templateSlice := (*[1 << 30]CAttr)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

	for i := 0; i < len(templateSlice); i++ {
		src := object.FindAttribute(templateSlice[i]._type)
		if src != nil {
			err := src.ToC(&templateSlice[i])
			if err != nil {
				return err
			}
		} else {
			return NewError("CryptoObject.CopyAttributes", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
		}
	}
	return nil
}
