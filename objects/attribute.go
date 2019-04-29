package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"bytes"
	"unsafe"
)

// An attribute related to a crypto object.
type Attribute struct {
	Type  int64
	Value []byte
}

// A map of attributes
type Attributes map[int64]*Attribute


func CToAttributes(pAttributes C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) Attributes {
	cAttrSlice := (*[1 << 30]C.CK_ATTRIBUTE)(unsafe.Pointer(pAttributes))[:ulCount:ulCount]

	attributes := make(Attributes, ulCount)
	for _, cAttr := range cAttrSlice {
		attr := CToAttribute(cAttr)
		attributes[attr.Type] = attr
	}
	return attributes
}

// Equals returns true if the maps of attributes are equal.
func (attributes Attributes) Equals(attributes2 Attributes) bool {
	if len(attributes) != len(attributes2) {
		return false
	}
	for attrType, attribute := range attributes {
		attribute2, ok := attributes2[attrType]
		if !ok {
			return false
		}
		if !attribute.Equals(attribute2) {
			return false
		}
	}
	return true
}

// Equals returns true if the attributes are equal.
func (attribute *Attribute) Equals(attribute2 *Attribute) bool {
	return attribute.Type == attribute2.Type &&
		bytes.Compare(attribute.Value, attribute2.Value) == 0
}

func CToAttribute(cAttr C.CK_ATTRIBUTE) *Attribute {
	attrType := cAttr._type
	attrVal := C.GoStringN(cAttr.pValue, cAttr.ulValueLen)
	return &Attribute{
		Type:  attrType,
		Value: attrVal,
	}
}

func (attribute *Attribute) ToC(cDst *C.CK_ATTRIBUTE) error {
	if cDst.pValue == nil {
		cDst.ulValueLen = len(attribute.Value)
		return nil
	}
	if cDst.ulValueLen >= len(attribute.Value) {
		cValue := C.CString(attribute.Value)
		cValueLen := len(attribute.Value)
		cDst._type = attribute.Type
		cDst.ulValueLen = cValueLen
		C.memcpy(cValue, cDst.pValue, cValueLen)
		C.free(unsafe.Pointer(cValue))
	} else {
		return NewError("Attribute.ToC", "Buffer too small", C.CKR_BUFFER_TOO_SMALL)
	}
	return nil
}