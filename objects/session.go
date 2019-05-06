package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"github.com/niclabs/tcrsa"
	"unsafe"
)

type Session struct {
	Slot *Slot
	Handle C.CK_SESSION_HANDLE
	flags C.CK_FLAGS
	KeyMetaInfo  tcrsa.KeyMeta
}

type Sessions map[C.CK_SESSION_HANDLE]*Session

var SessionHandle C.CK_SESSION_HANDLE = 0


func NewSession(flags C.CK_FLAGS, currentSlot *Slot) *Session {
	SessionHandle++
	return &Session{
		Slot: currentSlot,
		Handle: SessionHandle,
		flags: flags,
	}
}

func (session *Session) GetHandle() C.CK_SESSION_HANDLE {
	return session.Handle
}

func (session *Session) GetCurrentSlot() *Slot {
	return session.Slot
}

func (session *Session) isReadOnly() bool {
	return (session.flags & C.CKF_RW_SESSION) != C.CKF_RW_SESSION
}

func (session *Session) GetState() (int, error) {
	switch session.Slot.Token.GetSecurityLevel() {
	case SecurityOfficer:
		return C.CKS_RW_SO_FUNCTIONS, nil
	case User:
		if session.isReadOnly() {
			return C.CKS_RO_USER_FUNCTIONS, nil
		} else {
			return C.CKS_RW_USER_FUNCTIONS, nil
		}
	case Public:
		if session.isReadOnly() {
			return C.CKS_RO_PUBLIC_SESSION, nil
		} else {
			return C.CKS_RW_PUBLIC_SESSION, nil
		}
	}
	return 0, NewError("Session.GetState", "invalid security level", C.CK_ARGUMENTS_BAD)
}

func (session *Session) GetSessionInfo(pInfo C.CK_SESSION_INFO_PTR) error {
	if pInfo != nil {
		info := (C.CK_SESSION_INFO)(unsafe.Pointer(pInfo))
		info.slotID = session.Slot.ID
		info.state, err = session.GetState()
		if err != nil {
			
		}

	} else {
		return NewError("Session.GetSessionInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
}