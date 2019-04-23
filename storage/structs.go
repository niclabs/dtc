package storage

type TokenStorage interface {

	// Executes the logic necessary to initialize the storage.
	InitStorage() error

	// Saves a token into the storage, or returns an error.
	SaveToken(*Token) error

	// Retrieves a token from the storage or returns an error.
	GetToken(string) (*Token, error)

	// Returns the biggest number of a handle in the storage.
	GetMaxHandle() (int, error)

	// Finalizes the use of the storage. The storage is not usable
	// If this method is called.
	CloseStorage() error
}

// A token of the PKCS11 device.
type Token struct {
	Label   string
	Pin     string
	SoPin   string
	Objects []*CryptoObject
}

// A cryptoObject related to a token.
type CryptoObject struct {
	Handle     int
	Attributes []*Attribute
}

// An attribute related to a crypto object.
type Attribute struct {
	Type  string
	Value []byte
}
