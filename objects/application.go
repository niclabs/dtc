package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"dtcmaster/core"
	"dtcmaster/storage"
	"io"
)

type Application struct {
	Database storage.TokenStorage
	DTC      *core.DTC
	Slots    []*Slot
	Config   *core.Config
}

func NewApplication(out io.Writer) (app *Application, err error) {
	config, err := core.GetConfig()
	if err != nil {
		return
	}
	db, err := core.NewDatabase(config.Criptoki.DatabaseType)
	if err != nil {
		err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
		return
	}

	slots := make([]*Slot, len(config.Criptoki.Slots))

	for i, slotConf := range config.Criptoki.Slots {
		slot := &Slot{
			ID:          C.CK_SLOT_ID(i),
			Application: app,
		}
		token, err := db.GetToken(slotConf.Label)
		if err != nil {
			err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
			return
		}
		slot.InsertToken(token)
		slots[i] = slot
	}
	// TODO colocar el contexto del DTC
	app = &Application{
		Database: db,
		Slots:    slots,
		Config:   config,
	}
	return
}

func (app *Application) GetSessionSlot(handle C.CK_SESSION_HANDLE) (*Slot, error) {
	for _, slot := range app.Slots {
		if slot.hasSession(handle) {
			return slot, nil
		}
	}
	return nil, NewError("Application.GetSessionSlot", "session not found", C.CKR_SESSION_HANDLE_INVALID)
}

func (app *Application) GetSession(hSession C.CK_SESSION_HANDLE) (*Session, error) {
	slot, err := app.GetSessionSlot(hSession)
	if err != nil {
		return nil, err
	}
	session, err := slot.GetSession(hSession)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (app *Application) GetSlot(id C.CK_SLOT_ID) (*Slot, error) {
	if int(id) < len(app.Slots) {
		return nil, NewError("Application.GetSlot", "index out of bounds", C.CKR_SLOT_ID_INVALID)
	}
	return app.Slots[int(id)], nil
}
