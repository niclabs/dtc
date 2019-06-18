package objects
/*
#include <stdlib.h>
#include <string.h>
#include "../criptoki/pkcs11go.h"
*/
import "C"

type CULong = C.CK_ULONG

type CBool = C.CK_BBOOL
const CTrue = C.CK_TRUE
const CFalse = C.CK_FALSE

type CAttr = C.CK_ATTRIBUTE
type CAttrPointer = C.CK_ATTRIBUTE_PTR
type CAttrType = C.CK_ATTRIBUTE_TYPE
const CToken = C.CKA_TOKEN

type CryptoObjectType int

type CObjectHandle = C.CK_OBJECT_HANDLE
type CObjectClass = C.CK_OBJECT_CLASS

type CSessionHandle = C.CK_SESSION_HANDLE
type CSessionInfo = C.CK_SESSION_INFO
type CSessionInfoPointer = C.CK_SESSION_INFO_PTR

type CState = C.CK_STATE
type CFlags = C.CK_FLAGS

type CSlotID = C.CK_SLOT_ID
type CSlotInfoPointer = C.CK_SLOT_INFO_PTR
type CSlotInfo = C.CK_SLOT_INFO

type CMechanism = C.CK_MECHANISM
type CMechanismPtr = C.CK_MECHANISM_PTR
type CMechanismType = C.CK_MECHANISM_TYPE


type CUserType = C.CK_USER_TYPE

type CUTF8CharPtr = C.CK_UTF8CHAR_PTR

const CUnavailableInfo = C.CK_UNAVAILABLE_INFORMATION

type CTokenInfoPtr = C.CK_TOKEN_INFO_PTR
type CTokenInfo = C.CK_TOKEN_INFO
