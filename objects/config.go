package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"


const VersionMajor  = 1
const VersionMinor int = 0
const MinPinLen int = 3
const MaxPinLen int = 10
const MaxSessionCount int = 5