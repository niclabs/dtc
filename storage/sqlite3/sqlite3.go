package sqlite3

import (
	"database/sql"
	"dtcmaster/objects"
	"dtcmaster/storage"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

// DB is a wrapper over a sql.DB object, complying with storage
// interface.
type DB struct {
	*sql.DB
	ActualHandle int
}

// Creates the databases if they doesn't exist yet.
func (db DB) InitStorage() error {
	if err := db.createTables(); err != nil {
		return fmt.Errorf("create tables: %v", err)
	}
	if err := db.insertFirstToken(); err != nil {
		return fmt.Errorf("insert first token: %v", err)
	}
	return nil
}

func (db DB) SaveToken(token *objects.Token) error {
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

func (db DB) GetToken(label string) (token *objects.Token, err error) {
	// Retreive token
	tokenStmt, err := db.Prepare(GetTokenQuery)
	if err != nil {
		return
	}
	var pin, soPin string
	err = tokenStmt.QueryRow(label).Scan(&pin, &soPin)
	if err != nil {
		return
	}
	token = &objects.Token{
		Label: label,
		Pin:   pin,
		SoPin: soPin,
		Objects: make(objects.CryptoObjects, 0),
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
	var object *objects.CryptoObject
	for rows.Next() {
		err = rows.Scan(&aHandle, &aType, &aValue)
		if err != nil {
			return
		}
		object = &objects.CryptoObject{
			Handle:     aHandle,
			Attributes: make(objects.Attributes),
		}
		token.Objects = append(token.Objects, object)
		if aType.Valid && aValue != nil {
			object.Attributes[aType.Int64] = &objects.Attribute{
				Type:  aType.Int64,
				Value: aValue,
			}
		}
	}
	return
}

func (db DB) GetMaxHandle() (int, error) {
	err := db.updateMaxHandle()
	if err != nil {
		return -1, err
	}
	return db.ActualHandle, nil
}

func (db DB) CloseStorage() error {
	return db.Close()
}

func GetDatabase(path string) (storage.TokenStorage, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return &DB{
		DB: db,
	}, nil
}

func (db DB) createTables() error {
	for _, stmt := range CreateStmts {
		_, err := db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("in stmt %s: %v", stmt, err)
		}
	}
	return nil
}

func (db DB) insertFirstToken() error {
	stmt, err := db.Prepare(InsertTokenQuery)
	if err != nil {
		return err
	}
	_, err = stmt.Exec("TCBHSM", "1234", "1234")
	return err
}

func (db DB) updateMaxHandle() error {
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
