// Heavily based on tests found in github.com/miekg/pkcs11
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11_test

// These tests depend on SoftHSM and the library being in
// in /usr/lib/softhsm/libsofthsm.so

import (
	"bytes"
	"fmt"
	"github.com/miekg/pkcs11"
	"log"
	"math/big"
	"os"
	"testing"
)

var (
	module          = "../../dtc.so"
	tokenLabel      = "TCHSM"
	privateKeyLabel = "TCHSM_PK"
	pin             = "1234"
)

/*
This test supports the following environment variables:

* PKCS11_LIB: complete path to HSM Library
* PKCS11_TOKENLABEL
* PKCS11_PRIVKEYLABEL
* PKCS11_PIN
*/

func setenv(t *testing.T) *pkcs11.Ctx {
	if x := os.Getenv("PKCS11_LIB"); x != "" {
		module = x
	}
	t.Logf("loading %s", module)
	p := pkcs11.New(module)
	if p == nil {
		t.Fatal("Failed to init lib")
	}
	return p
}

func TestSetenv(t *testing.T) {
	if x := os.Getenv("PKCS11_LIB"); x != "" {
		module = x
	}
	p := pkcs11.New(module)
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	p.Destroy()
	return
}

func getSession(p *pkcs11.Ctx, t *testing.T) pkcs11.SessionHandle {
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e)
	}
	slots, e := p.GetSlotList(true)
	if e != nil {
		t.Fatalf("slots %s\n", e)
	}
	session, e := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if e != nil {
		t.Fatalf("session %s\n", e)
	}
	if e := p.Login(session, pkcs11.CKU_USER, pin); e != nil {
		t.Fatalf("user pin %s\n", e)
	}
	return session
}

func TestInitialize(t *testing.T) {
	p := setenv(t)
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e)
	}
	p.Finalize()
	p.Destroy()
}

func TestNew(t *testing.T) {
	if p := pkcs11.New(""); p != nil {
		t.Fatalf("init should have failed, got %v\n", p)
	}
	if p := pkcs11.New("/does/not/exist"); p != nil {
		t.Fatalf("init should have failed, got %v\n", p)
	}
}

func finishSession(p *pkcs11.Ctx, session pkcs11.SessionHandle) {
	p.Logout(session)
	p.CloseSession(session)
	p.Finalize()
	p.Destroy()
}

func TestGetInfo(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)
	info, err := p.GetInfo()
	if err != nil {
		t.Fatalf("non zero error %s\n", err)
	}
	if info.ManufacturerID != "NICLabs" {
		t.Fatalf("ID should be NICLabs and is %s", info.ManufacturerID)
	}
	t.Logf("%+v\n", info)
}

func TestFindObject(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel := "TestFindObject"

	// There are 2 keys in the db with this tag
	generateRSAKeyPair(t, p, session, tokenLabel, false)

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel)}
	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("failed to init: %s\n", e)
	}
	obj, _, e := p.FindObjects(session, 2)
	if e != nil {
		t.Fatalf("failed to find: %s\n", e)
	}
	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("failed to finalize: %s\n", e)
	}
	if len(obj) != 2 {
		t.Fatal("should have found two objects")
	}
}

func TestGetAttributeValue(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	pbk, _ := generateRSAKeyPair(t, p, session, "GetAttributeValue", false)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(pbk), template)
	if err != nil {
		t.Fatalf("err %s\n", err)
	}
	for i, a := range attr {
		t.Logf("attr %d, type %d, valuelen %d", i, a.Type, len(a.Value))
		if a.Type == pkcs11.CKA_MODULUS {
			mod := big.NewInt(0)
			mod.SetBytes(a.Value)
			t.Logf("modulus %s\n", mod.String())
		}
	}
}

func TestDigest(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	testDigest(t, p, session, []byte("this is a string"), "517592df8fec3ad146a79a9af153db2a4d784ec5")
	finishSession(p, session)
}

func testDigest(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, input []byte, expected string) {
	e := p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	if e != nil {
		t.Fatalf("DigestInit: %s\n", e)
	}

	hash, e := p.Digest(session, input)
	if e != nil {
		t.Fatalf("digest: %s\n", e)
	}
	hex := ""
	for _, d := range hash {
		hex += fmt.Sprintf("%02x", d)
	}
	if hex != expected {
		t.Fatalf("wrong digest: %s", hex)
	}
}

func TestDigesUpdate(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	testDigestUpdate(t, p, session, [][]byte{[]byte("this is "), []byte("a string")}, "517592df8fec3ad146a79a9af153db2a4d784ec5")
	finishSession(p, session)
}

func testDigestUpdate(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, inputs [][]byte, expected string) {
	if e := p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)}); e != nil {
		t.Fatalf("DigestInit: %s\n", e)
	}
	for _, input := range inputs {
		if e := p.DigestUpdate(session, input); e != nil {
			t.Fatalf("DigestUpdate: %s\n", e)
		}
	}
	hash, e := p.DigestFinal(session)
	if e != nil {
		t.Fatalf("DigestFinal: %s\n", e)
	}
	hex := ""
	for _, d := range hash {
		hex += fmt.Sprintf("%02x", d)
	}
	if hex != expected {
		t.Fatalf("wrong digest: %s", hex)
	}
}

/*
Purpose: Generate RSA keypair with a given name and persistence.
Inputs: test object
	context
	session handle
	tokenLabel: string to set as the token labels
	tokenPersistent: boolean. Whether or not the token should be
			session based or persistent. If false, the
			token will not be saved in the HSM and is
			destroyed upon termination of the session.
Outputs: creates persistent or ephemeral tokens within the HSM.
Returns: object handles for public and private keys. Fatal on error.
*/
func generateRSAKeyPair(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, tokenLabel string, tokenPersistent bool) (pkcs11.ObjectHandle, pkcs11.ObjectHandle) {
	/*
		inputs: test object, context, session handle
			tokenLabel: string to set as the token labels
			tokenPersistent: boolean. Whether or not the token should be
					session based or persistent. If false, the
					token will not be saved in the HSM and is
					destroyed upon termination of the session.
		outputs: creates persistent or ephemeral tokens within the HSM.
		returns: object handles for public and private keys.
	*/

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 1024),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	pbk, pvk, e := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if e != nil {
		t.Fatalf("failed to generate keypair: %s\n", e)
	}

	return pbk, pvk
}

func TestGenerateKeyPair(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)
	tokenLabel := "TestGenerateKeyPair"
	generateRSAKeyPair(t, p, session, tokenLabel, false)
}

func TestSign(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel := "TestSign"
	_, pvk := generateRSAKeyPair(t, p, session, tokenLabel, false)

	p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA1_RSA_PKCS, nil)}, pvk)
	_, e := p.Sign(session, []byte("Sign me!"))
	if e != nil {
		t.Fatalf("failed to sign: %s\n", e)
	}
}

/* destroyObject
Purpose: destroy and object from the HSM
Inputs: test handle
	session handle
	searchToken: String containing the token label to search for.
	class: Key type (pkcs11.CKO_PRIVATE_KEY or CKO_PUBLIC_KEY) to remove.
Outputs: removes object from HSM
Returns: Fatal error on failure.
*/
func destroyObject(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, searchToken string, class uint) (err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, searchToken),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}

	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("failed to init: %s\n", e)
	}
	obj, _, e := p.FindObjects(session, 1)
	if e != nil || len(obj) == 0 {
		t.Fatalf("failed to find objects")
	}
	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("failed to finalize: %s\n", e)
	}

	if e := p.DestroyObject(session, obj[0]); e != nil {
		t.Fatalf("DestroyObject failed: %s\n", e)
	}
	return
}

// Create and destroy persistent keys
func TestDestroyObject(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	generateRSAKeyPair(t, p, session, "TestDestroyKey", true)
	if e := destroyObject(t, p, session, "TestDestroyKey", pkcs11.CKO_PUBLIC_KEY); e != nil {
		t.Fatalf("Failed to destroy object: %s\n", e)
	}
	if e := destroyObject(t, p, session, "TestDestroyKey", pkcs11.CKO_PRIVATE_KEY); e != nil {
		t.Fatalf("Failed to destroy object: %s\n", e)
	}

}

func TestSymmetricEncryption(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)
	if info, err := p.GetInfo(); err != nil {
		t.Errorf("GetInfo: %v", err)
		return
	} else if info.ManufacturerID == "SoftHSM" && info.LibraryVersion.Major < 2 {
		t.Skipf("AES not implemented on SoftHSM")
	}
	tokenLabel := "TestGenerateKey"
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 16),
	}
	key, err := p.GenerateKey(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
		keyTemplate)
	if err != nil {
		t.Fatalf("failed to generate keypair: %s\n", err)
	}
	t.Run("Encrypt", func(t *testing.T) {
		t.Run("ECB", func(t *testing.T) {
			testEncrypt(t, p, session, key, pkcs11.CKM_AES_ECB, make([]byte, 32), nil)
		})
		t.Run("CBC", func(t *testing.T) {
			testEncrypt(t, p, session, key, pkcs11.CKM_AES_CBC, make([]byte, 32), make([]byte, 16))
		})
		t.Run("CBC-PAD", func(t *testing.T) {
			testEncrypt(t, p, session, key, pkcs11.CKM_AES_CBC_PAD, make([]byte, 31), make([]byte, 16))
		})
		/* Broken in SoftHSMv2
		t.Run("Empty", func(t *testing.T) {
			testEncrypt(t, p, session, key, pkcs11.CKM_AES_CBC, []byte{}, make([]byte, 16))
		})
		*/
	})
	t.Run("EncryptUpdate", func(t *testing.T) {
		t.Run("ECB", func(t *testing.T) {
			testEncryptUpdate(t, p, session, key, pkcs11.CKM_AES_ECB, [][]byte{make([]byte, 32), make([]byte, 16)}, nil)
		})
		t.Run("CBC", func(t *testing.T) {
			testEncryptUpdate(t, p, session, key, pkcs11.CKM_AES_CBC, [][]byte{make([]byte, 32), make([]byte, 16)}, make([]byte, 16))
		})
		t.Run("CBC-PAD", func(t *testing.T) {
			testEncryptUpdate(t, p, session, key, pkcs11.CKM_AES_CBC_PAD, [][]byte{make([]byte, 11), make([]byte, 20)}, make([]byte, 16))
		})
		/* Broken in SoftHSMv2
		t.Run("Empty", func(t *testing.T) {
			testEncryptUpdate(t, p, session, key, pkcs11.CKM_AES_CBC, [][]byte{make([]byte, 31), []byte{}}, make([]byte, 16))
		})
		*/
	})
}

func testEncrypt(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, mech uint, plaintext []byte, iv []byte) {
	var err error
	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, iv)}, key); err != nil {
		t.Fatalf("EncryptInit: %s\n", err)
	}
	var ciphertext []byte
	if ciphertext, err = p.Encrypt(session, plaintext); err != nil {
		t.Fatalf("Encrypt: %s\n", err)
	}
	if err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, iv)}, key); err != nil {
		t.Fatalf("DecryptInit: %s\n", err)
	}
	var decrypted []byte
	if decrypted, err = p.Decrypt(session, ciphertext); err != nil {
		t.Fatalf("Decrypt: %s\n", err)
	}
	if bytes.Compare(plaintext, decrypted) != 0 {
		t.Fatalf("Plaintext mismatch")
	}
}

func testEncryptUpdate(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle, mech uint, plaintexts [][]byte, iv []byte) {
	var err error
	if err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, iv)}, key); err != nil {
		t.Fatalf("EncryptInit: %s\n", err)
	}
	var ciphertexts [][]byte
	var output, plaintext []byte
	for _, input := range plaintexts {
		plaintext = append(plaintext, input...)
		if output, err = p.EncryptUpdate(session, input); err != nil {
			t.Fatalf("EncryptUpdate: %s\n", err)
		}
		ciphertexts = append(ciphertexts, output)
	}
	if output, err = p.EncryptFinal(session); err != nil {
		t.Fatalf("EncryptFinal: %s\n", err)
	}
	ciphertexts = append(ciphertexts, output)
	if err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, iv)}, key); err != nil {
		t.Fatalf("DecryptInit: %s\n", err)
	}
	var decrypted []byte
	for _, input := range ciphertexts {
		if len(input) == 0 { // Broken in SoftHSMv2
			continue
		}
		if output, err = p.DecryptUpdate(session, input); err != nil {
			t.Fatalf("DecryptUpdate: %s\n", err)
		}
		decrypted = append(decrypted, output...)
	}
	if output, err = p.DecryptFinal(session); err != nil {
		t.Fatalf("DecryptFinal: %s\n", err)
	}
	decrypted = append(decrypted, output...)
	if bytes.Compare(plaintext, decrypted) != 0 {
		t.Fatalf("Plaintext mismatch")
	}
}

// ExampleSign shows how to sign some data with a private key.
// Note: error correction is not implemented in this example.
func ExampleCtx_Sign() {
	lib := "/usr/lib/softhsm/libsofthsm.so"
	if x := os.Getenv("PKCS11_LIB"); x != "" {
		lib = x
	}
	p := pkcs11.New(lib)
	if p == nil {
		log.Fatal("Failed to init lib")
	}

	p.Initialize()
	defer p.Destroy()
	defer p.Finalize()
	slots, _ := p.GetSlotList(true)
	session, _ := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	defer p.CloseSession(session)
	p.Login(session, pkcs11.CKU_USER, pin)
	defer p.Logout(session)
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 1024),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "ExampleSign"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "ExampleSign"),
	}
	_, priv, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		log.Fatal(err)
	}
	p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA1_RSA_PKCS, nil)}, priv)
	// Sign something with the private key.
	data := []byte("Lets sign this data")

	_, err = p.Sign(session, data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("It works!")
	// Output: It works!
}

// Copyright 2013 Miek Gieben. All rights reserved.
