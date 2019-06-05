package message


type MessageType byte

const (
	None MessageType = iota
	SendKeyShare
	AskForSigShare
)

var TypeToString = map[MessageType]string{
	None: "Undefined type",
	SendKeyShare: "Send Key Share",
	AskForSigShare: "Ask for Signature Share",
}

func (mType MessageType) String() string {
	if name, ok := TypeToString[mType]; ok {
		return name
	} else {
		return "Unknown Message"
	}
}


