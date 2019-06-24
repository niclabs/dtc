package main

import (
	"fmt"
)

func NewDatabase(dbType string) (TokenStorage, error) {
	switch dbType {
	case "sqlite3":
		sqliteConfig, err := GetSqlite3Config()
		if err != nil {
			return nil, fmt.Errorf("sqlite3 config not defined")
		}
		return GetDatabase(sqliteConfig.Path)
	default:
		return nil,NewError("NewDatabase", fmt.Sprintf("storage option not found: '%s'", dbType), 0)
	}
}
