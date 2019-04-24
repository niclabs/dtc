package objects

type SecurityLevel int

const (
	SecurityOfficer SecurityLevel = iota
	User
	Public
)
