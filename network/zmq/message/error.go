package message

import "fmt"

type NodeError uint8

const (
	// c'est ne pas un err
	Ok NodeError = iota
	// Invalid message
	InvalidMessageError
	// Network Errors
	ReceiveMessageError
	ParseMessageError
	SendResponseError
	// Signature Reception Errors
	AlreadyInitializedError
	KeyShareDecodeError
	KeyMetaDecodeError
	// Signing Errors
	NotInitializedError
	DocSignError
	SigShareEncodeError
	// Invalid error number (keep at the end)
	UnknownError = NodeError(1<<8 - 1)
)

var ErrorToString = map[NodeError]string{
	Ok:                  "not an error",
	InvalidMessageError:	"invalid message",
	ReceiveMessageError: "cannot receive message",
	ParseMessageError:   "cannot parse received message",
	SendResponseError:   "cannot send response",
	AlreadyInitializedError:   "Node was already initialized",
	KeyShareDecodeError: "cannot decode received Key Share",
	KeyMetaDecodeError:  "cannot decode received Key Metainformation",
	NotInitializedError: "node not initialized with the server",
	DocSignError:        "cannot sign the document",
	SigShareEncodeError: "cannot encode the signature to a message",
	UnknownError:        "unknown error",
}

func (err NodeError) Error() string {
	if int(err) >= len(ErrorToString) {
		return ErrorToString[UnknownError]
	}
	return ErrorToString[err]
}

func (err NodeError) ComposeError(err2 error) string {
	return fmt.Sprintf("%s: %s", err.Error(), err2.Error())
}
