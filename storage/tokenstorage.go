package storage

import "dtcmaster/objects"

type TokenStorage interface {
	// Executes the logic necessary to initialize the storage.
	InitStorage() error

	// Saves a token into the storage, or returns an error.
	SaveToken(*objects.Token) error

	// Retrieves a token from the storage or returns an error.
	GetToken(string) (*objects.Token, error)

	// Returns the biggest number of a handle in the storage.
	GetMaxHandle() (int, error)

	// Finalizes the use of the storage. The storage is not usable
	// If this method is called.
	CloseStorage() error
}
