package objects

import "C"
import "unsafe"

type CMechanism = C.CK_MECHANISM
type CMechanismPtr = C.CK_MECHANISM_PTR
type CMechanismType = C.CK_MECHANISM_TYPE

type Mechanism struct {
	Type      C.CK_MECHANISM_TYPE
	Parameter []byte
}


func CToMechanism(pMechanism CMechanismPtr) *Mechanism {
	cMechanism :=(*CMechanism)(unsafe.Pointer(pMechanism))
	mechanismType := cMechanism._type
	mechanismVal := C.GoStringN(unsafe.Pointer(cMechanism.pValue), C.int(cMechanism.ulValueLen))
	return &CMechanism{
		Type:  mechanismType,
		Value: mechanismVal,
	}

}


func (mechanism *Mechanism)ToC(pMechanism C.CK_MECHANISM_PTR) error {
	return nil
}
