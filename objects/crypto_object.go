package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import "unsafe"

// The type of the cryptoObject
type CryptoObjectType int

const (
	SessionObject CryptoObjectType = iota
	TokenObject
)

// A cryptoObject related to a token.
type CryptoObject struct {
	Handle     int
	Type       CryptoObjectType
	Attributes Attributes
}

// A map of cryptoobjects
type CryptoObjects map[int]*CryptoObject

var ActualHandle = 0

func CToCryptoObject(pAttributes C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, coType CryptoObjectType) *CryptoObject {
	attrSlice := CToAttributes(pAttributes, ulCount)
	ActualHandle++
	object := &CryptoObject{
		Handle:     ActualHandle,
		Type:       coType,
		Attributes: attrSlice,
	}
	return object
}

// Equals returns true if the maps of crypto objects are equal.
func (objects CryptoObjects) Equals(objects2 CryptoObjects) bool {
	if len(objects) != len(objects2) {
		return false
	}
	for handle, object := range objects {
		object2, ok := objects2[handle]
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
func (object *CryptoObject) Match(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) bool {
	templateSlice := (*[1 << 30]C.CK_ATTRIBUTE)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

	for _, cTmpl := range templateSlice {
		ourAttr, ok := object.Attributes[cTmpl._type]
		theirTempVal := C.GoStringN(cTmpl.pValue, cTmpl.ulValueLen)
		if !ok || ourAttr.Value == theirTempVal {
			return false
		}
	}
	return true
}

func (object *CryptoObject) FindAttribute(tmpl *C.CK_ATTRIBUTE) *Attribute {
	template := (C.CK_ATTRIBUTE)(unsafe.Pointer(tmpl))
	if attr, ok := object.Attributes[template._type]; ok {
		return attr
	}
	return nil
}

// https://stackoverflow.com/questions/28925179/cgo-how-to-pass-struct-array-from-c-to-go#28933938
func (object *CryptoObject) CopyAttributes(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
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

func (object *CryptoObject) GetType() CryptoObjectType {
	return object.Type
}

func (object *CryptoObject) GetHandle() int {
	return object.Handle
}

func (object *CryptoObject) GetAttributes() Attributes {
	return object.Attributes
}
