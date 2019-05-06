package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"strings"
	"unsafe"
)

type Slot struct {
	ID       int64
	flags    uint64
	token    *Token
	Sessions Sessions
	Application *Application
}

func (slot *Slot) IsTokenPresent() bool {
	return slot.token != nil
}


func (slot *Slot) OpenSession(flags C.CK_FLAGS) (C.CK_SESSION_HANDLE, error) {
	if slot.IsTokenPresent() {
		return 0, NewError("Slot.OpenSession", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
	session := &Session{
		flags: flags,
	}
	handle := session.GetHandle()
	slot.Sessions[handle] = session
	// TODO: mutex?
	return handle, nil
}

func (slot *Slot) CloseSession(handle C.CK_SESSION_HANDLE) error {
	if slot.IsTokenPresent() {
		return NewError("Slot.CloseSession", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
	if _, err := slot.GetSession(handle); err != nil {
		return err
	}
	delete(slot.Sessions, handle)
	return nil
}

func (slot *Slot) CloseAllSessions() {
	slot.Sessions = make(Sessions, 0)
}

func (slot *Slot) GetSession(handle C.CK_SESSION_HANDLE) (*Session, error) {
	if slot.IsTokenPresent() {
		return nil, NewError("Slot.GetSession", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
	if session, ok := slot.Sessions[handle]; ok {
		return nil, NewError("Slot.CloseSession", "session handle doesn't exist in this slot", C.CKR_SESSION_HANDLE_INVALID)
	} else {
		return session, nil
	}
}

func (slot *Slot) hasSession(handle C.CK_SESSION_HANDLE) bool {
	_, ok := slot.Sessions[handle]
	return ok
}


func (slot *Slot) GetInfo (pInfo C.CK_SLOT_INFO_PTR) error {
	if pInfo == nil {
		return NewError("Slot.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (C.CK_SLOT_INFO)(unsafe.Pointer(pInfo))

	description := "TCHSM Slot"
	description += strings.Repeat(" ", 64 - len(description)) // spaces
	cDescription := C.CString(description)
	defer C.free(unsafe.Pointer(cDescription))
	C.strncpy(info.slotDescription, cDescription, 64)

	manufacturerID := "Nic Chile Research Labs"
	manufacturerID += strings.Repeat(" ", 32 - len(manufacturerID))
	cManufacturerID := C.CString(manufacturerID)
	defer C.free(unsafe.Pointer(cManufacturerID))
	C.strncpy(info.manufacturerID, cManufacturerID, 32)

	pInfo.flags = slot.flags
	pInfo.hardwareVersion.major = VersionMajor
	pInfo.hardwareVersion.minor = VersionMinor
	pInfo.firmwareVersion.major = VersionMajor
	pInfo.firmwareVersion.minor = VersionMinor
	return nil
}

func (slot *Slot) GetToken() (*Token, error) {
	if slot.IsTokenPresent() {
		return slot.token, nil
	} else {
		return nil, NewError("Slot.GetToken", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
}

func (slot *Slot) InsertToken(token *Token) {
	slot.token = token
}