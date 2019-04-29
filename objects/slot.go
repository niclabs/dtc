package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"

type Slot struct {
	ID C.CK_SLOT_ID
	Flags C.CK_FLAGS
	Token *Token
	Sessions Sessions
}