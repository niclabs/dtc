package main
/*
#include "pkcs11go.h"
*/
import "C"
import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

type Sqlite3Config struct {
	Path string
}

func GetSqlite3Config() (*Sqlite3Config, error) {
	var conf Sqlite3Config
	err := viper.UnmarshalKey("sqlite3", &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}

// Sqlite3DB is a wrapper over a sql.Sqlite3DB object, complying with storage
// interface.
type Sqlite3DB struct {
	*sql.DB
	ActualHandle int
}

// Creates the databases if they doesn't exist yet.
func (db Sqlite3DB) InitStorage() error {
	if err := db.createTables(); err != nil {
		return fmt.Errorf("create tables: %v", err)
	}
	if err := db.insertFirstToken(); err != nil {
		return fmt.Errorf("insert first token: %v", err)
	}
	return nil
}

func (db Sqlite3DB) SaveToken(token *Token) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	// Preparing statements
	tokenStmt, err := tx.Prepare(InsertTokenQuery)
	if err != nil {
		return err
	}
	objectStmt, err := tx.Prepare(InsertCryptoObjectQuery)
	if err != nil {
		return err
	}
	attrStmt, err := tx.Prepare(InsertAttributeQuery)
	if err != nil {
		return err
	}
	// Cleaning old CryptoObjects
	cleanObjectStmt, err := tx.Prepare(CleanCryptoObjectsQuery)
	if err != nil {
		return err
	}
	if _, err := cleanObjectStmt.Exec(token.Label); err != nil {
		return err
	}
	// Cleaning old attributes
	cleanAttrsStmt, err := tx.Prepare(CleanAttributesQuery)
	if err != nil {
		return err
	}
	if _, err := cleanAttrsStmt.Exec(token.Label); err != nil {
		return err
	}
	// Saving the token
	if _, err := tokenStmt.Exec(token.Label, token.Pin, token.SoPin); err != nil {
		return err
	}
	// Saving the CryptoObjects
	for _, object := range token.Objects {
		if _, err := objectStmt.Exec(token.Label); err != nil {
			return err
		}
		object.Handle, err = db.GetMaxHandle()
		if err != nil {
			return err
		}
		// Saving the attributes
		for _, attr := range object.Attributes {
			if _, err := attrStmt.Exec(token.Label, object.Handle, attr.Type, attr.Value); err != nil {
				return err
			}
		}
	}
	// Committing
	return tx.Commit()
}

func (db Sqlite3DB) GetToken(label string) (token *Token, err error) {
	// Retrieve token
	tokenStmt, err := db.Prepare(GetTokenQuery)
	if err != nil {
		return
	}
	var pin, soPin string
	err = tokenStmt.QueryRow(label).Scan(&pin, &soPin)
	if err != nil {
		return
	}
	token = &Token{
		Label: label,
		Pin:   pin,
		SoPin: soPin,
		Objects: make(CryptoObjects, 0),
	}

	attrsStmt, err := db.Prepare(GetCryptoObjectAttrsQuery)
	if err != nil {
		return
	}
	rows, err := attrsStmt.Query(label)
	if err != nil {
		return
	}
	defer rows.Close()
	var aHandle int
	var aType sql.NullInt64
	var aValue []byte
	var object *CryptoObject
	for rows.Next() {
		err = rows.Scan(&aHandle, &aType, &aValue)
		if err != nil {
			return
		}
		object = &CryptoObject{
			Handle:     C.CK_OBJECT_HANDLE(aHandle),
			Attributes: make(Attributes),
		}
		token.Objects = append(token.Objects, object)
		if aType.Valid && aValue != nil {
			object.Attributes[C.CK_ATTRIBUTE_TYPE(aType.Int64)] = &Attribute{
				Type:  C.CK_ATTRIBUTE_TYPE(aType.Int64),
				Value: aValue,
			}
		}
	}
	return
}

func (db Sqlite3DB) GetMaxHandle() (C.CK_ULONG, error) {
	err := db.updateMaxHandle()
	if err != nil {
		return 0, err
	}
	return C.CK_ULONG(db.ActualHandle), nil
}

func (db Sqlite3DB) CloseStorage() error {
	return db.Close()
}

func GetDatabase(path string) (TokenStorage, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return &Sqlite3DB{
		DB: db,
	}, nil
}

func (db Sqlite3DB) createTables() error {
	for _, stmt := range CreateStmts {
		_, err := db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("in stmt %s: %v", stmt, err)
		}
	}
	return nil
}

func (db Sqlite3DB) insertFirstToken() error {
	stmt, err := db.Prepare(InsertTokenQuery)
	if err != nil {
		return err
	}
	_, err = stmt.Exec("TCBHSM", "1234", "1234")
	return err
}

func (db Sqlite3DB) updateMaxHandle() error {
	rows, err := db.Query(GetMaxHandleQuery)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		var maxHandle int
		if err := rows.Scan(&maxHandle); err != nil {
			return err
		}
		db.ActualHandle = maxHandle
	} else {
		return rows.Err()
	}
	return nil
}
