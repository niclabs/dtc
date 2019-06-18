package objects

type TokenStorage interface {
	// Executes the logic necessary to initialize the storage.
	InitStorage() error

	// Saves a token into the storage, or returns an error.
	SaveToken(*Token) error

	// Retrieves a token from the storage or returns an error.
	GetToken(string) (*Token, error)

	// Returns the biggest number of a handle in the storage.
	GetMaxHandle() (CULong, error)

	// Finalizes the use of the storage. The storage is not usable
	// If this method is called.
	CloseStorage() error
}
