package main

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"github.com/google/uuid"
	"github.com/niclabs/dtcnode/message"
	"github.com/niclabs/tcrsa"
	"hash"
	"math/rand"
	"reflect"
	"sync"
	"unsafe"
)

const AttrTypeKeyHandler = 1 << 31
const AttrTypeKeyMeta = 1<<31 + 1

type Session struct {
	sync.Mutex
	Slot           *Slot
	Handle         C.CK_SESSION_HANDLE
	flags          C.CK_FLAGS
	refreshedToken bool
	// finding things
	findInitialized bool
	foundObjects    []C.CK_OBJECT_HANDLE
	// signing things
	signMechanism   *Mechanism
	signKeyName     string
	signKeyMeta     *tcrsa.KeyMeta
	signData        []byte
	signInitialized bool
	// verifying things
	verifyMechanism   *Mechanism
	verifyKeyName     string
	verifyKeyMeta     *tcrsa.KeyMeta
	verifyData        []byte
	verifyInitialized bool
	// hashing things
	digestHash        hash.Hash
	digestInitialized bool
	// random
	randSrc *rand.Rand
}

type Sessions map[C.CK_SESSION_HANDLE]*Session

var SessionHandle = C.CK_SESSION_HANDLE(0)

func NewSession(flags C.CK_FLAGS, currentSlot *Slot) *Session {
	SessionHandle++

	return &Session{
		Slot:    currentSlot,
		Handle:  SessionHandle,
		flags:   flags,
		randSrc: rand.New(rand.NewSource(int64(rand.Int()))),
	}
}

func (session *Session) GetHandle() C.CK_SESSION_HANDLE {
	return session.Handle
}

func (session *Session) GetCurrentSlot() *Slot {
	return session.Slot
}

func (session *Session) GetInfo(pInfo C.CK_SESSION_INFO_PTR) error {
	if pInfo != nil {
		state, err := session.GetState()
		if err != nil {
			return err
		}
		info := (*C.CK_SESSION_INFO)(unsafe.Pointer(pInfo))
		info.slotID = C.CK_SLOT_ID(session.Slot.ID)
		info.state = C.CK_STATE(state)
		info.flags = C.CK_FLAGS(session.flags)
		return nil

	} else {
		return NewError("Session.GetSessionInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
}

// Saves an object and sets its handle.
func (session *Session) CreateObject(attrs Attributes) (*CryptoObject, error) {
	if attrs == nil {
		return nil, NewError("Session.CreateObject", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	isTokenAttr, err := attrs.GetAttributeByType(C.CKA_TOKEN)
	if err != nil {
		return nil, NewError("Session.CreateObject", "is_token attr not defined", C.CKR_ARGUMENTS_BAD)
	}

	isToken := uint8(isTokenAttr.Value[0]) != 0
	var objType CryptoObjectType

	if isToken {
		objType = TokenObject
	} else {
		objType = SessionObject
	}

	object := &CryptoObject{
		Type:       objType,
		Attributes: attrs,
	}

	token := session.Slot.token
	isPrivate := true
	oClass := C.CK_OBJECT_CLASS(C.CKO_VENDOR_DEFINED)
	keyType := C.CK_KEY_TYPE(C.CKK_VENDOR_DEFINED)

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

	if isToken && session.isReadOnly() {
		return nil, NewError("Session.CreateObject", "session is read only", C.CKR_SESSION_READ_ONLY)
	}
	state, err := session.GetState()
	if err != nil {
		return nil, err
	}
	if !GetUserAuthorization(state, isToken, isPrivate, true) {
		return nil, NewError("Session.CreateObject", "user not logged in", C.CKR_USER_NOT_LOGGED_IN)
	}

	switch oClass {
	case C.CKO_PUBLIC_KEY, C.CKO_PRIVATE_KEY:
		if keyType == C.CKK_RSA {
			token.AddObject(object)
			err := session.GetCurrentSlot().Application.Database.SaveToken(token)
			if err != nil {
				return nil, NewError("Session.CreateObject", err.Error(), C.CKR_DEVICE_ERROR)
			}
			return object, nil
		} else {
			return nil, NewError("Session.CreateObject", "key type not supported yet", C.CKR_ATTRIBUTE_VALUE_INVALID)
		}
	}
	return nil, NewError("Session.CreateObject", "object class not supported yet", C.CKR_ATTRIBUTE_VALUE_INVALID)
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

func (session *Session) FindObjectsInit(attrs Attributes) error {
	if session.findInitialized {
		return NewError("Session.FindObjectsInit", "operation already initialized", C.CKR_OPERATION_ACTIVE)
	}
	token, err := session.GetCurrentSlot().GetToken()
	if err != nil {
		return err
	}

	if len(attrs) == 0 {
		session.foundObjects = make([]C.CK_OBJECT_HANDLE, len(token.Objects))
		i := 0
		for _, object := range token.Objects {
			session.foundObjects[i] = object.Handle
			i++
		}
	} else {
		session.foundObjects = make([]C.CK_OBJECT_HANDLE, 0)
		for _, object := range token.Objects {
			if object.Match(attrs) {
				session.foundObjects = append(session.foundObjects, object.Handle)
			}
		}
	}

	// Si no se encontro el objeto, recargar la base de datos y buscar de
	// nuevo, puede que el objeto haya sido creado por otra instancia.
	if len(attrs) == 0 && len(session.foundObjects) == 0 && !session.refreshedToken {
		session.refreshedToken = true
		slot := session.GetCurrentSlot()
		token, err := slot.GetToken()
		if err != nil {
			return err
		}
		db := slot.Application.Database
		newToken, err := db.GetToken(token.Label)
		if err != nil {
			return NewError("Session.DestroyObject", err.Error(), C.CKR_DEVICE_ERROR)
		}
		token.CopyState(newToken)
		slot.InsertToken(newToken)
		return session.FindObjectsInit(attrs)
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
	if int(maxObjectCount) < limit {
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

func (session *Session) GetObject(handle C.CK_OBJECT_HANDLE) (*CryptoObject, error) {
	token, err := session.Slot.GetToken()
	if err != nil {
		return nil, err
	}
	object, err := token.GetObject(handle)
	if err != nil {
		return nil, err
	}
	return object, nil
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
	return 0, NewError("Session.GetState", "invalid security level", C.CKR_ARGUMENTS_BAD)
}

func (session *Session) isReadOnly() bool {
	return (session.flags & C.CKF_RW_SESSION) != C.CKF_RW_SESSION
}

func (session *Session) Login(userType C.CK_USER_TYPE, pin string) error {
	token, err := session.Slot.GetToken()
	if err != nil {
		return err
	}
	return token.Login(userType, pin)
}

func (session *Session) Logout() error {
	token, err := session.Slot.GetToken()
	if err != nil {
		return err
	}
	token.Logout()
	return nil
}

func (session *Session) GetDTC() (*DTC, error) {
	if session.Slot == nil {
		return nil, NewError("Session.GetDTC", "slot null", C.CKR_DEVICE_ERROR)
	} else if session.Slot.Application == nil {
		return nil, NewError("Session.GetDTC", "application null in slot", C.CKR_DEVICE_ERROR)

	} else if session.Slot.Application.DTC == nil {
		return nil, NewError("Session.GetDTC", "dtc null in application", C.CKR_DEVICE_ERROR)
	}
	return session.Slot.Application.DTC, nil
}


func (session *Session) GenerateKeyPair(mechanism *Mechanism, pkAttrs, skAttrs Attributes) (pkObject, skObject *CryptoObject, err error) {
	// TODO: Verify access permissions (in my defense, the original implementation didn't do that too)
	if mechanism == nil || pkAttrs == nil || skAttrs == nil { // maybe this should be 0?
		err = NewError("Session.GenerateKeyPair", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
		return
	}

	bitSizeAttr, err := pkAttrs.GetAttributeByType(C.CKA_MODULUS_BITS)
	if err != nil {
		err = NewError("Session.GenerateKeyPair", "got NULL pointer", C.CKR_TEMPLATE_INCOMPLETE)
		return
	}

	bitSize := binary.LittleEndian.Uint64(bitSizeAttr.Value)

	switch mechanism.Type {
	case C.CKM_RSA_PKCS_KEY_PAIR_GEN:
		// TODO: check if this UUID had been used before (?)
		keyID := uuid.New().String()
		var dtc *DTC
		dtc, err = session.GetDTC()
		if err != nil {
			return
		}
		var keyMeta *tcrsa.KeyMeta
		var pk, sk Attributes
		keyMeta, err = dtc.CreateNewKey(keyID, int(bitSize), nil)
		if err != nil {
			return
		}
		pk, err = createPublicKey(keyID, pkAttrs, keyMeta)
		if err != nil {
			return
		}
		pkObject, err = session.CreateObject(pk)
		if err != nil {
			return
		}
		sk, err = createPrivateKey(keyID, skAttrs, keyMeta)
		if err != nil {
			return
		}
		skObject, err = session.CreateObject(sk)
		if err != nil {
			return
		}
	default:
		return nil, nil, NewError("Session.GenerateKeyPair", "mechanism invalid", C.CKR_MECHANISM_INVALID)
	}
	return pkObject, skObject, nil
}

func (session *Session) SignInit(mechanism *Mechanism, hKey C.CK_OBJECT_HANDLE) error {
	if session.signInitialized {
		return NewError("Session.SignInit", "operation active", C.CKR_OPERATION_ACTIVE)
	}
	if mechanism == nil {
		return NewError("Session.SignInit", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	keyObject, err := session.GetObject(hKey)
	if err != nil {
		return err
	}
	keyNameAttr := keyObject.FindAttribute(AttrTypeKeyHandler)
	if keyNameAttr == nil {
		return NewError("Session.SignInit", "object handle does not contain any key", C.CKR_ARGUMENTS_BAD)
	}
	keyMetaAttr := keyObject.FindAttribute(AttrTypeKeyMeta)
	if keyMetaAttr == nil {
		return NewError("Session.SignInit", "object handle does not contain any key metainfo", C.CKR_ARGUMENTS_BAD)
	}

	session.signKeyMeta, err = message.DecodeKeyMeta(keyMetaAttr.Value)
	if err != nil {
		return NewError("Session.SignInit", "key metainfo is corrupt", C.CKR_ARGUMENTS_BAD)
	}
	session.signKeyName = string(keyNameAttr.Value)
	session.signMechanism = mechanism
	session.signData = make([]byte, 0)
	session.signInitialized = true
	return nil
}

func (session *Session) SignLength() (C.ulong, error) {
	if !session.signInitialized {
		return 0, NewError("Session.SignLength", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	return C.ulong(session.signKeyMeta.PublicKey.Size()), nil
}

func (session *Session) SignUpdate(data []byte) error {
	if !session.signInitialized {
		return NewError("Session.SignLength", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	session.signData = append(session.signData, data...)
	return nil
}

func (session *Session) SignFinal() ([]byte, error) {
	if !session.signInitialized {
		return nil, NewError("Session.SignFinal", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	// First we prepare the data
	prepared, err := session.signMechanism.Prepare(
		session.randSrc,
		session.signKeyMeta.PublicKey.Size(),
		session.signData,
	)
	if err != nil {
		return nil, err
	}
	// Now we sign the data with our nodes and return the signature
	sign, err := session.Slot.Application.DTC.SignData(session.signKeyName, session.signKeyMeta, prepared)
	if err != nil {
		return nil, err
	}
	session.signKeyMeta = nil
	session.signKeyName = ""
	session.signData = nil
	session.signInitialized = false // TODO: should this be restarted if error, too?
	return sign, nil
}

func (session *Session) VerifyInit(mechanism *Mechanism, hKey C.CK_OBJECT_HANDLE) error {
	if session.verifyInitialized {
		return NewError("Session.VerifyInit", "operation active", C.CKR_OPERATION_ACTIVE)
	}
	if mechanism == nil {
		return NewError("Session.VerifyInit", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	keyObject, err := session.GetObject(hKey)
	if err != nil {
		return err
	}
	keyNameAttr := keyObject.FindAttribute(AttrTypeKeyHandler)
	if keyNameAttr == nil {
		return NewError("Session.VerifyInit", "object handle does not contain any key", C.CKR_ARGUMENTS_BAD)
	}
	keyMetaAttr := keyObject.FindAttribute(AttrTypeKeyMeta)
	if keyMetaAttr == nil {
		return NewError("Session.VerifyInit", "object handle does not contain any key metainfo", C.CKR_ARGUMENTS_BAD)
	}

	session.signKeyMeta, err = message.DecodeKeyMeta(keyMetaAttr.Value)
	if err != nil {
		return NewError("Session.VerifyInit", "key metainfo is corrupt", C.CKR_ARGUMENTS_BAD)
	}
	session.signKeyName = string(keyNameAttr.Value)
	session.signMechanism = mechanism
	session.signData = make([]byte, 0)
	session.signInitialized = true
	return nil
}

func (session *Session) VerifyLength() (uint64, error) {
	if !session.verifyInitialized {
		return 0, NewError("Session.verifyLength", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	return uint64(session.verifyKeyMeta.PublicKey.Size()), nil
}

func (session *Session) VerifyUpdate(data []byte) error {
	if !session.verifyInitialized {
		return NewError("Session.VerifyLength", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	session.verifyData = append(session.signData, data...)
	return nil
}

func (session *Session) VerifyFinal(signature []byte) error {
	if !session.verifyInitialized {
		return NewError("Session.VerifyFinal", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	err := session.verifyMechanism.Verify(
		session.verifyKeyMeta.PublicKey,
		session.verifyData,
		signature,
	)
	session.verifyKeyMeta = nil
	session.verifyKeyName = ""
	session.verifyData = nil
	session.verifyInitialized = false
	return err
}

func (session *Session) DigestInit(mechanism *Mechanism) error {
	if session.digestInitialized {
		return NewError("Session.DigestInit", "operation active", C.CKR_OPERATION_ACTIVE)
	}
	if mechanism == nil {
		return NewError("Session.DigestInit", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	hashType, err := mechanism.GetHashType()
	if err != nil {
		return err
	}

	if hashType <= 0 || hashType >= crypto.BLAKE2b_512 {
		return NewError("Session.DigestInit", "mechanism invalid", C.CKR_MECHANISM_INVALID)
	}

	session.digestHash = hashType.New()
	session.digestInitialized = true
	return nil
}

func (session *Session) Digest(data []byte) ([]byte, error) {
	if !session.digestInitialized {
		return nil, NewError("Session.DigestInit", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	if data == nil {
		return nil, NewError("Session.DigestInit", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	_, err := session.digestHash.Write(data)
	if err != nil {
		return nil, err
	}
	hashed := session.digestHash.Sum(nil)
	session.digestInitialized = false
	session.digestHash = nil
	return hashed, nil
}

func (session *Session) GenerateRandom(size int) ([]byte, error) {
	out := make([]byte, size)
	randLen, err := session.randSrc.Read(out)
	if err != nil {
		return nil, NewError("Session.GenerateRandom", fmt.Sprintf("%s", err.Error()), C.CKR_DEVICE_ERROR)
	}
	if randLen != size {
		return nil, NewError("Session.GenerateRandom", "random data acquired is not as big as requested", C.CKR_DEVICE_ERROR)
	}
	return out, nil
}

func (session *Session) SeedRandom(seed []byte) {
	seedInt := int64(0)
	for i := 0; i < len(seed); i += 8 {
		var f int
		if len(seed) < i+8 {
			f = len(seed)
		} else {
			f = i + 8
		}
		slice := seed[i:f]
		seedInt += int64(binary.LittleEndian.Uint64(slice)) // it overflows
	}
	session.randSrc.Seed(seedInt)
}

func createPublicKey(keyID string, pkAttrs Attributes, keyMeta *tcrsa.KeyMeta) (Attributes, error) {

	// This fields are defined in SoftHSM implementation
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_CLASS, []byte{C.CKO_PUBLIC_KEY}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_KEY_TYPE, []byte{C.CKK_RSA}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_KEY_GEN_MECHANISM, []byte{C.CKM_RSA_PKCS_KEY_PAIR_GEN}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_LOCAL, []byte{C.CK_TRUE}})

	// This fields are our defaults

	pkAttrs.SetIfUndefined(&Attribute{C.CKA_LABEL, nil})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_ID, nil})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_SUBJECT, nil})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_PRIVATE, []byte{C.CK_FALSE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_MODIFIABLE, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_TOKEN, []byte{C.CK_FALSE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_DERIVE, []byte{C.CK_FALSE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_ENCRYPT, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_VERIFY, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_VERIFY_RECOVER, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_WRAP, []byte{C.CK_TRUE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_TRUSTED, []byte{C.CK_FALSE}})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_START_DATE, make([]byte, 8)})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_END_DATE, make([]byte, 8)})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_MODULUS_BITS, nil})

	// E and N from PK

	eBytes := make([]byte, reflect.TypeOf(keyMeta.PublicKey.E).Size())
	binary.LittleEndian.PutUint64(eBytes, uint64(keyMeta.PublicKey.E))

	pkAttrs.SetIfUndefined(&Attribute{C.CKA_MODULUS, keyMeta.PublicKey.N.Bytes()})
	pkAttrs.SetIfUndefined(&Attribute{C.CKA_PUBLIC_EXPONENT, eBytes})

	// Custom Fields

	encodedKeyMeta, err := encodeKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	pkAttrs.SetIfUndefined(&Attribute{AttrTypeKeyHandler, []byte(keyID)})
	pkAttrs.SetIfUndefined(&Attribute{AttrTypeKeyMeta, encodedKeyMeta})

	return pkAttrs, nil
}

func createPrivateKey(keyID string, skAttrs Attributes, keyMeta *tcrsa.KeyMeta) (Attributes, error) {

	// This fields are defined in SoftHSM implementation
	skAttrs.SetIfUndefined(&Attribute{C.CKA_CLASS, []byte{C.CKO_PRIVATE_KEY}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_KEY_TYPE, []byte{C.CKK_RSA}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_KEY_GEN_MECHANISM, []byte{C.CKM_RSA_PKCS_KEY_PAIR_GEN}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_LOCAL, []byte{C.CK_TRUE}})

	// This fields are our defaults

	skAttrs.SetIfUndefined(&Attribute{C.CKA_LABEL, nil})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_ID, nil})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_SUBJECT, nil})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_PRIVATE, []byte{C.CK_FALSE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_MODIFIABLE, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_TOKEN, []byte{C.CK_FALSE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_DERIVE, []byte{C.CK_FALSE}})

	skAttrs.SetIfUndefined(&Attribute{C.CKA_WRAP_WITH_TRUSTED, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_ALWAYS_AUTHENTICATE, []byte{C.CK_FALSE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_SENSITIVE, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_ALWAYS_SENSITIVE, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_DECRYPT, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_SIGN, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_DECRYPT, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_SIGN_RECOVER, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_UNWRAP, []byte{C.CK_TRUE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_EXTRACTABLE, []byte{C.CK_FALSE}})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_NEVER_EXTRACTABLE, []byte{C.CK_TRUE}})

	skAttrs.SetIfUndefined(&Attribute{C.CKA_START_DATE, make([]byte, 8)})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_END_DATE, make([]byte, 8)})

	// E and N from PK

	eBytes := make([]byte, reflect.TypeOf(keyMeta.PublicKey.E).Size())
	binary.LittleEndian.PutUint64(eBytes, uint64(keyMeta.PublicKey.E))

	skAttrs.SetIfUndefined(&Attribute{C.CKA_MODULUS, keyMeta.PublicKey.N.Bytes()})
	skAttrs.SetIfUndefined(&Attribute{C.CKA_PUBLIC_EXPONENT, eBytes})

	// Custom Fields

	encodedKeyMeta, err := encodeKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	skAttrs.SetIfUndefined(&Attribute{AttrTypeKeyHandler, []byte(keyID)})
	skAttrs.SetIfUndefined(&Attribute{AttrTypeKeyMeta, encodedKeyMeta})

	return skAttrs, nil
}

func encodeKeyMeta(meta *tcrsa.KeyMeta) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(meta); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func GetUserAuthorization(state C.CK_STATE, isToken, isPrivate, userAction bool) bool {
	switch state {
	case C.CKS_RW_SO_FUNCTIONS:
		return !isPrivate
	case C.CKS_RW_USER_FUNCTIONS:
		return true
	case C.CKS_RO_USER_FUNCTIONS:
		if isToken {
			return !userAction
		} else {
			return true
		}
	case C.CKS_RW_PUBLIC_SESSION:
		return !isPrivate
	case C.CKS_RO_PUBLIC_SESSION:
		return false
	}
	return false
}
