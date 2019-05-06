package storage

import (
	"dtcmaster/objects"
	"dtcmaster/storage/sqlite3"
	"fmt"
)

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


func NewDatabase(dbType string) (TokenStorage, error) {
	switch dbType {
	case "sqlite3":
		sqliteConfig, err := sqlite3.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("sqlite3 config not defined")
		}
		return sqlite3.GetDatabase(sqliteConfig.Path)
	default:
		return nil, fmt.Errorf("storage option not found")
	}
	// TODO: More storage options.
}
