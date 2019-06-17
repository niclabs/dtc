package objects

/*
#include "../criptoki/pkcs11go.h"
*/
import "C"
import (
	"dtc/core"
)

type Application struct {
	Database TokenStorage
	DTC      *core.DTC
	Slots    []*Slot
	Config   *core.Config
}

func NewApplication() (app *Application, err error) {
	config, err := core.GetConfig()
	if err != nil {
		return
	}
	db, err := NewDatabase(config.Criptoki.DatabaseType)
	if err != nil {
		err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
		return
	}

	slots := make([]*Slot, len(config.Criptoki.Slots))

	for i, slotConf := range config.Criptoki.Slots {
		slot := &Slot{
			ID:          CSlotID(i),
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
	dtc, err := core.NewDTC(config.DTC)
	if err != nil {
		return
	}
	app = &Application{
		Database: db,
		Slots:    slots,
		Config:   config,
		DTC:      dtc,
	}
	return
}

func (app *Application) GetSessionSlot(handle CSessionHandle) (*Slot, error) {
	for _, slot := range app.Slots {
		if slot.HasSession(handle) {
			return slot, nil
		}
	}
	return nil, NewError("Application.GetSessionSlot", "session not found", C.CKR_SESSION_HANDLE_INVALID)
}

func (app *Application) GetSession(handle CSessionHandle) (*Session, error) {
	slot, err := app.GetSessionSlot(handle)
	if err != nil {
		return nil, err
	}
	session, err := slot.GetSession(handle)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (app *Application) GetSlot(id CSlotID) (*Slot, error) {
	if int(id) < len(app.Slots) {
		return nil, NewError("Application.GetSlot", "index out of bounds", C.CKR_SLOT_ID_INVALID)
	}
	return app.Slots[int(id)], nil
}
