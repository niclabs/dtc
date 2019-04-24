package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import "fmt"

type TcbError struct {
	Who string
	Description string
	Code C.CK_RV
}


func NewError(who, description string, code C.CK_RV) *TcbError {
	return &TcbError{
		Who: who,
		Description: description,
		Code: code,
	}
}

func (err TcbError) Error() string {
	return fmt.Sprintf("%s: %s", err.Who, err.Description)
}