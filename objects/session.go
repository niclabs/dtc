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
	findInitialized bool
	refreshedToken bool
	foundObjects []C.CK_OBJECT_HANDLE
}

type Sessions map[C.CK_SESSION_HANDLE]*Session

var SessionHandle = C.CK_SESSION_HANDLE(0)


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

func (session *Session) GetState() (C.CK_STATE, error) {
	switch session.Slot.token.GetSecurityLevel() {
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

func (session *Session) GetInfo(pInfo C.CK_SESSION_INFO_PTR) error {
	if pInfo != nil {
		state, err := session.GetState()
		if err != nil {
			return err
		}
		info := (C.CK_SESSION_INFO)(unsafe.Pointer(pInfo))
		info.slotID = C.CK_SLOT_ID(session.Slot.ID)
		info.state = C.CK_STATE(state)
		info.flags = C.CK_FLAGS(session.flags)
		return nil

	} else {
		return NewError("Session.GetSessionInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
}


func (session *Session) CreateObject(pAttributes C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (C.CK_OBJECT_HANDLE, error) {
	if pAttributes == nil {
		return 0, NewError("Session.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	token := session.Slot.token
	object, err := CToCryptoObject(pAttributes, ulCount)
	if err != nil {
		return 0, err
	}
	isToken := C.CK_FALSE
	isPrivate := C.CK_TRUE
	oClass := C.CKO_VENDOR_DEFINED
	keyType := C.CKK_VENDOR_DEFINED

	isToken = object.Type == TokenObject

	privAttr, err := object.Attributes.GetAttributeByType(C.CKA_PRIVATE)
	if err == nil && len(privAttr.Value) > 0 {
		isPrivate = C.CK_BBOOL(privAttr.Value[0]) == C.CK_TRUE
	}

	classAttr, err := object.Attributes.GetAttributeByType(C.CKA_CLASS)
	if err == nil && len(classAttr.Value) > 0 {
		oClass = C.CK_OBJECT_CLASS(classAttr.Value[0])
	}

	keyTypeAttr, err := object.Attributes.GetAttributeByType(C.CKA_KEY_TYPE)
	if err == nil && len(classAttr.Value) > 0 {
		keyType = C.CK_KEY_TYPE(keyTypeAttr.Value[0])
	}

	if isToken == C.CK_TRUE && session.isReadOnly() {
		return 0, NewError("Session.CreateObject", "session is read only", C.CKR_SESSION_READ_ONLY)
	}
	state, err := session.GetState()
	if err != nil {
		return 0, err
	}
	if !GetUserAuthorization(state, isToken, isPrivate, true) {
		return 0, NewError("Session.CreateObject", "user not logged in", C.CKR_USER_NOT_LOGGED_IN)
	}

	switch oClass{
	case C.CKO_PUBLIC_KEY, C.CKO_PRIVATE_KEY:
		if keyType == C.CKK_RSA {
			handle := token.AddObject(object)
			err := session.GetCurrentSlot().Application.Database.SaveToken(token)
			if err != nil {
				return 0, NewError("Session.CreateObject", err.Error(), C.CKR_DEVICE_ERROR)
			}
			return handle, nil
		} else {
			return 0, NewError("Session.CreateObject", "key type not supported yet", C.CKR_ATTRIBUTE_VALUE_INVALID)
		}
	}
	return 0, NewError("Session.CreateObject", "object class not supported yet", C.CKR_ATTRIBUTE_VALUE_INVALID)
	// TODO: Verificar que los objetos sean válidos
}

func (session *Session) DestroyObject(hObject C.CK_OBJECT_HANDLE) error {
	token, err := session.Slot.GetToken()
	if err != nil {
		return err
	}
	if object, err := token.GetObject(hObject); err != nil {
		return err
	} else {
		attr := object.FindAttribute(C.CKA_VENDOR_DEFINED)
		if attr != nil {
			privateAttr := object.FindAttribute(C.CKA_PRIVATE)
			if privateAttr != nil {
				isPrivate := C.CK_BBOOL(privateAttr.Value[0]) == C.CK_TRUE
				if isPrivate {
					// TODO: Delete key shares from DTC core
				}
			}
		}
		_ = token.DeleteObject(hObject)
		err := session.GetCurrentSlot().Application.Database.SaveToken(token)
		if err != nil {
			return NewError("Session.DestroyObject", err.Error(), C.CKR_DEVICE_ERROR)
		}
		return nil
	}
}

func (session *Session) FindObjectsInit(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
	if session.findInitialized {
		return NewError("Session.FindObjectsInit", "operation already initialized", C.CKR_OPERATION_ACTIVE)
	}
	if pTemplate == nil {
		return NewError("Session.FindObjectsInit", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	token, err := session.GetCurrentSlot().GetToken()
	if err != nil {
		return err
	}

	if uint64(ulCount) == 0 {
		session.foundObjects = make([]C.CK_OBJECT_HANDLE, len(token.Objects))
		i := 0
		for handle, _ := range token.Objects {
			session.foundObjects[i] = handle
			i++
		}
	} else {
		session.foundObjects = make([]C.CK_OBJECT_HANDLE, 0)
		for handle, object := range token.Objects {
			if object.Match(pTemplate, ulCount) {
				session.foundObjects = append(session.foundObjects, handle)
			}
		}
	}

	// Si no se encontro el objecto, recargar la base de datos y buscar de
	// nuevo, puede que el objeto haya sido creado por otra instancia.
	if ulCount != 0 && len(session.foundObjects) == 0 && !session.refreshedToken {
		session.refreshedToken = true
		slot := session.GetCurrentSlot()
		token, err := slot.GetToken()
		if err != nil {
			return err
		}
		db := slot.Application.Database
		newToken, err:= db.GetToken(token.Label)
		if err != nil {
			return NewError("Session.DestroyObject", err.Error(), C.CKR_DEVICE_ERROR)
		}
		token.CopyState(newToken)
		slot.InsertToken(newToken)
		return session.FindObjectsInit(pTemplate, ulCount)
	}

	// TODO: Verificar permisos de acceso
	session.findInitialized = true
	return nil
}

func (session *Session) FindObjects(maxObjectCount C.CK_ULONG) ([]C.CK_OBJECT_HANDLE, error) {
	if !session.findInitialized {
		return nil, NewError("Session.FindObjects", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	limit := len(session.foundObjects)
	if int(maxObjectCount) >= limit {
		limit = int(maxObjectCount)
	}
	resul := session.foundObjects[:limit]
	session.foundObjects = session.foundObjects[limit:]
	return resul, nil
}

func (session *Session) FindObjectsFinal() error {
	if !session.findInitialized {
		return NewError("Session.FindObjectsFinal", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	} else {
		session.findInitialized = false
		session.refreshedToken = false
	}
	return nil
}

func GetUserAuthorization(state C.CK_STATE, isToken, isPrivate C.CK_BBOOL, userAction bool) bool {
	switch state {
	case C.CKS_RW_SO_FUNCTIONS:
		return isPrivate == C.CK_FALSE
	case C.CKS_RW_USER_FUNCTIONS:
		return true
	case C.CKS_RO_USER_FUNCTIONS:
		if isToken == C.CK_TRUE {
			return !userAction
		} else {
			return true
		}
	case C.CKS_RW_PUBLIC_SESSION:
		return isPrivate == C.CK_FALSE
	case C.CKS_RO_PUBLIC_SESSION:
		return false
	}
	return false
}