package core

import (
	"dtcmaster/storage"
	"dtcmaster/storage/sqlite3"
	"fmt"
)

func NewDatabase(dbType string) (storage.TokenStorage, error) {
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