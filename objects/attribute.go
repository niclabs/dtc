package objects

/*
#include <stdlib.h>
#include <string.h>
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"bytes"
	"unsafe"
)

// An attribute related to a crypto object.
type Attribute struct {
	Type  CAttrType
	Value []byte
}

// A map of attributes
type Attributes map[CAttrType]*Attribute

func CToAttributes(pAttributes CAttrPointer, ulCount CULong) (Attributes, error) {
	if ulCount <= 0 {
		return nil, NewError("CToAttributes", "cannot transform: ulcount is not greater than 0", C.CKR_BUFFER_TOO_SMALL)
	}

	cAttrSlice := (*[1 << 30]CAttr)(unsafe.Pointer(pAttributes))[:ulCount:ulCount]

	attributes := make(Attributes, ulCount)
	for _, cAttr := range cAttrSlice {
		attr := CToAttribute(cAttr)
		attributes[attr.Type] = attr
	}
	return attributes, nil
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

// Adds an attribute only if it doesn't exist
func (attributes Attributes) SetIfUndefined(attr *Attribute) bool {
	if _, ok := attributes[attr.Type]; !ok {
		attributes[attr.Type] = attr
		return true
	}
	return false
}

func CToAttribute(cAttr CAttr) *Attribute {
	attrType := cAttr._type
	attrVal := C.GoBytes(unsafe.Pointer(cAttr.pValue), C.int(cAttr.ulValueLen))
	return &Attribute{
		Type:  attrType,
		Value: attrVal,
	}
}

func (attribute *Attribute) ToC(cDst CAttrPointer) error {
	if cDst.pValue == nil {
		cDst.ulValueLen = CULong(len(attribute.Value))
		return nil
	}
	if cDst.ulValueLen >= CULong(len(attribute.Value)) {
		cValue := C.CBytes(attribute.Value)
		cValueLen := CULong(len(attribute.Value))
		cDst._type = attribute.Type
		cDst.ulValueLen = cValueLen
		C.memcpy(unsafe.Pointer(cDst.pValue), unsafe.Pointer(cValue), cValueLen)
		C.free(unsafe.Pointer(cValue))
	} else {
		return NewError("Attribute.ToC", "Buffer too small", C.CKR_BUFFER_TOO_SMALL)
	}
	return nil
}

// Equals returns true if the attributes are equal.
func (attribute *Attribute) Equals(attribute2 *Attribute) bool {
	return attribute.Type == attribute2.Type &&
		bytes.Compare(attribute.Value, attribute2.Value) == 0
}

func (attributes Attributes) GetAttributeByType(cAttr CAttrType) (*Attribute, error) {
	attr, ok := attributes[cAttr]
	if ok {
		return attr, nil
	}
	return nil, NewError("Attributes.GetAttributeByType", "attribute doesn't exist", C.CKR_ATTRIBUTE_VALUE_INVALID) // TODO: is this error code ok?
}
