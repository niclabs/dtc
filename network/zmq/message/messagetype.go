package message

type Type byte

const (
	None Type = iota
	SendKeyShare
	AskForSigShare
)

var TypeToString = map[Type]string{
	None:           "Undefined type",
	SendKeyShare:   "Send Key Share",
	AskForSigShare: "Ask for Signature Share",
}

func (mType Type) String() string {
	if name, ok := TypeToString[mType]; ok {
		return name
	} else {
		return "Unknown Message"
	}
}
