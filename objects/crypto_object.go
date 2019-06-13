package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import "unsafe"

// The type of the cryptoObject
type CryptoObjectType int

// Type of handle
type CCryptoObjectHandle = C.CK_OBJECT_HANDLE

const (
	SessionObject CryptoObjectType = iota
	TokenObject
)

// A cryptoObject related to a token.
type CryptoObject struct {
	Handle     CCryptoObjectHandle
	Type       CryptoObjectType
	Attributes Attributes
}

// A map of cryptoobjects
type CryptoObjects []*CryptoObject

func CToCryptoObject(pAttributes CAttrPointer, ulCount C.CK_ULONG) (*CryptoObject, error) {
	attrSlice := CToAttributes(pAttributes, ulCount)
	var coType CryptoObjectType
	tokenAttr, ok := attrSlice[C.CKA_TOKEN]
	if !ok {
		return nil, NewError("CToCryptoObject", "Token attribute not found", C.CK_ATTRIBUTE_VALUE_INVALID)
	}
	isToken := C.CK_BBOOL(tokenAttr.Value[0])
	if isToken == C.CK_FALSE {
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
	for handle, object := range objects {
		ok := false
		var object2 *CryptoObject
		for _, object2 = range objects2 {
			if object2.Handle == handle {
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
func (object *CryptoObject) Match(pTemplate CAttrPointer, ulCount C.CK_ULONG) bool {
	templateSlice := (*[1 << 30]CAttr)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

	for _, cTmpl := range templateSlice {
		ourAttr, ok := object.Attributes[cTmpl._type]
		theirTempVal := C.GoStringN(cTmpl.pValue, cTmpl.ulValueLen)
		if !ok || ourAttr.Value == theirTempVal {
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
func (object *CryptoObject) CopyAttributes(pTemplate CAttrPointer, ulCount C.CK_ULONG) error {
	if pTemplate == nil {
		return NewError("CryptoObject.CopyAttributes", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	templateSlice := (*[1 << 30]C.CK_ATTRIBUTE)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

	for i := 0; i < len(templateSlice); i++ {
		src := object.FindAttribute(templateSlice[i])
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
