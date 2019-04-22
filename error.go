package main

type DTCError int

const (
	None  DTCError = iota
	NoMem
	ConfigFile
	Connection
	Communication
	Serialization
	Database
	Intern
	InvalidVal
	TimedOut
)
