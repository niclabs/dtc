package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"github.com/niclabs/tcrsa"
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