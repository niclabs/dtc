package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"

type Slot struct {
	ID       int64
	Flags    uint64
	Token    *Token
	Sessions Sessions
}
