package message

import (
	"crypto/rand"
	"fmt"
)

func GetRandomHexString(len int) (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return "", err
	}
	return fmt.Sprintf("%X", b), nil
}
