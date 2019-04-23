package sqlite3

import (
	"database/sql"
	"dtcmaster/storage"
	_ "github.com/mattn/go-sqlite3"
	"strconv"
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
		return err
	}
	if err := db.insertFirstToken(); err != nil {
		return err
	}

	return nil
}

func (db DB) SaveToken(token *storage.Token) error {
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
		if _, err := objectStmt.Exec(token.Label, object.Handle); err != nil {
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

func (db DB) GetToken(label string) (token *storage.Token, err error) {
	// Conseguir Token
	tokenStmt, err := db.Prepare(GetTokenQuery)
	if err != nil {
		return
	}
	var pin, soPin string
	err = tokenStmt.QueryRow(label).Scan(&pin, &soPin)
	token = &storage.Token{
		Label: label,
		Pin:   pin,
		SoPin: soPin,
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
	cryptoObjects := make(map[string]*storage.CryptoObject)
	var aHandle string
	var aType sql.NullString
	var aValue []byte
	var iHandle int
	var object *storage.CryptoObject
	var ok bool
	for rows.Next() {
		err = rows.Scan(&aHandle, &aType, &aValue)
		if err != nil {
			return
		}
		if object, ok = cryptoObjects[aHandle]; !ok {
			iHandle, err = strconv.Atoi(aHandle)
			if err != nil {
				return
			}
			object = &storage.CryptoObject{
				Handle:     iHandle,
				Attributes: make([]*storage.Attribute, 1),
			}
			cryptoObjects[aHandle] = object
		}
		if aType.Valid && aValue != nil {
			object.Attributes = append(object.Attributes, &storage.Attribute{
				Type:  aType.String,
				Value: aValue,
			})
		}
	}

	// Append cryptoobjects to Token
	token.Objects = make([]*storage.CryptoObject, len(cryptoObjects))
	i := 0
	for _, cryptoObject := range cryptoObjects {
		token.Objects[i] = cryptoObject
		i++
	}
	return
}

func (db DB) GetMaxHandle() (int, error) {
	err := db.updateMaxHandle()
	if err != nil {
		return 0, err
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
			return err
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
	rows, err := db.Query(GetMaxHandle)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&db.ActualHandle); err != nil {
			return err
		}
	} else {
		return rows.Err()
	}
	return nil
}
