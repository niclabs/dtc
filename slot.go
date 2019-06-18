package main

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"strings"
	"sync"
	"unsafe"
)

type Slot struct {
	ID       C.CK_SLOT_ID
	flags    uint64
	token    *Token
	Sessions Sessions
	Application *Application
	sync.Mutex
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
	slot.Lock()
	defer slot.Unlock()
	slot.Sessions[handle] = session
	return handle, nil
}

func (slot *Slot) CloseSession(handle C.CK_SESSION_HANDLE) error {
	if slot.IsTokenPresent() {
		return NewError("Slot.CloseSession", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
	if _, err := slot.GetSession(handle); err != nil {
		return err
	}
	slot.Lock()
	defer slot.Unlock()
	delete(slot.Sessions, handle)
	return nil
}

func (slot *Slot) CloseAllSessions() {
	slot.Lock()
	defer slot.Unlock()
	slot.Sessions = make(Sessions, 0)
}

func (slot *Slot) GetSession(handle C.CK_SESSION_HANDLE) (*Session, error) {
	if slot.IsTokenPresent() {
		return nil, NewError("Slot.GetSession", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
	slot.Lock()
	defer slot.Unlock()
	if session, ok := slot.Sessions[handle]; ok {
		return nil, NewError("Slot.CloseSession", "session handle doesn't exist in this slot", C.CKR_SESSION_HANDLE_INVALID)
	} else {
		return session, nil
	}
}

func (slot *Slot) HasSession(handle C.CK_SESSION_HANDLE) bool {
	slot.Lock()
	defer slot.Unlock()
	_, ok := slot.Sessions[handle]
	return ok
}


func (slot *Slot) GetInfo (pInfo C.CK_SLOT_INFO_PTR) error {
	if pInfo == nil {
		return NewError("Slot.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_SLOT_INFO)(unsafe.Pointer(pInfo))

	description := slot.Application.Config.Criptoki.Description
	if len(description) > 64 {
		description = description[:64]
	}
	description += strings.Repeat(" ", 64 - len(description)) // spaces
	cDescription := C.CBytes([]byte(description), len(description))
	defer C.free(unsafe.Pointer(cDescription))
	C.memcpy(unsafe.Pointer(&info.slotDescription[0]), cDescription, 64)

	manufacturerID := slot.Application.Config.Criptoki.ManufacturerID
	if len(manufacturerID) > 64 {
		manufacturerID = manufacturerID[:64]
	}
	manufacturerID += strings.Repeat(" ", 32 - len(manufacturerID))
	cManufacturerID := C.CBytes([]byte(manufacturerID))
	defer C.free(unsafe.Pointer(cManufacturerID))
	C.memcpy(unsafe.Pointer(&info.manufacturerID[0]), cManufacturerID, 32)

	pInfo.flags = C.CK_ULONG(slot.flags)
	pInfo.hardwareVersion.major = C.uchar(slot.Application.Config.Criptoki.VersionMajor)
	pInfo.hardwareVersion.minor = C.uchar(slot.Application.Config.Criptoki.VersionMinor)
	pInfo.firmwareVersion.major = C.uchar(slot.Application.Config.Criptoki.VersionMajor)
	pInfo.firmwareVersion.minor = C.uchar(slot.Application.Config.Criptoki.VersionMinor)
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
	token.slot = slot
}
