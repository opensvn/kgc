package kgc

import (
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm9"
)

func TestNewKgc(t *testing.T) {
	kgc := New()
	if kgc == nil {
		t.Error("kgc is nil")
	}

	if kgc.EncryptMasterKey == nil {
		t.Error("kgc.encryptMasterKey is nil")
	}

	if kgc.SignMasterKey == nil {
		t.Error("kgc.signMasterKey is nil")
	}
}

func TestGetSignMasterPublicKey(t *testing.T) {
	kgc := New()
	if kgc == nil {
		t.Error("kgc is nil")
	}

	signMasterPublicKey := kgc.GetSignMasterPublicKey()
	if signMasterPublicKey == nil {
		t.Error("signMasterPublicKey is nil")
	}
}

func TestGenerateUserSignKey(t *testing.T) {
	kgc := New()
	if kgc == nil {
		t.Error("kgc is nil")
	}

	uid := []byte("opensvn")
	hid := byte(0x01)
	userSignKey, err := kgc.GenerateUserSignKey(uid, hid)
	if err != nil {
		t.Error(err)
	}

	if userSignKey == nil {
		t.Error("userSignKey is nil")
	}
}

func TestGetEncryptMasterPublicKey(t *testing.T) {
	kgc := New()
	if kgc == nil {
		t.Error("kgc is nil")
	}

	encryptMasterPublicKey := kgc.GetEncryptMasterPublicKey()
	if encryptMasterPublicKey == nil {
		t.Error("signMasterPublicKey is nil")
	}
}

func TestGenerateUserEncryptKey(t *testing.T) {
	kgc := New()
	if kgc == nil {
		t.Error("kgc is nil")
	}

	uid := []byte("opensvn")
	hid := byte(0x01)
	userEncryptKey, err := kgc.GenerateUserEncryptKey(uid, hid)
	if err != nil {
		t.Error(err)
	}

	if userEncryptKey == nil {
		t.Error("userSignKey is nil")
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	kgc1 := New()
	if kgc1 == nil {
		t.Error("kgc is nil")
	}

	uid := []byte("alice")
	hid := byte(0x01)
	userEncryptKey, err := kgc1.GenerateUserEncryptKey(uid, hid)
	if err != nil {
		t.Error(err)
	}
	masterPublicKey := kgc1.GetEncryptMasterPublicKey()

	kgc2 := New()
	if kgc2 == nil {
		t.Error("kgc is nil")
	}

	uid2 := []byte("bob")
	hid2 := byte(0x01)
	userEncryptKey2, err := kgc2.GenerateUserEncryptKey(uid2, hid2)
	if err != nil {
		t.Error(err)
	}
	masterPublicKey2 := kgc2.GetEncryptMasterPublicKey()

	plainText := []byte("hello world")

	// alice encrypt plainText to bob
	cipher, err := sm9.EncryptASN1(rand.Reader, masterPublicKey2, uid2, hid2, plainText)
	if err != nil {
		t.Fatal(err)
	}

	// bob decrypt cipher to plainText
	got, err := sm9.DecryptASN1(userEncryptKey2, uid2, cipher)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(plainText) {
		t.Errorf("expected %v, got %v\n", string(plainText), string(got))
	}

	// bob encrypt plainText to alice
	cipher, err = sm9.EncryptASN1(rand.Reader, masterPublicKey, uid, hid, plainText)
	if err != nil {
		t.Fatal(err)
	}

	// alice decrypt cipher to plainText
	got, err = sm9.DecryptASN1(userEncryptKey, uid, cipher)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(plainText) {
		t.Errorf("expected %v, got %v\n", string(plainText), string(got))
	}
}

func TestSignAndVerify(t *testing.T) {
	kgc1 := New()
	if kgc1 == nil {
		t.Error("kgc is nil")
	}

	uid := []byte("alice")
	hid := byte(0x01)
	userSignKey, err := kgc1.GenerateUserSignKey(uid, hid)
	if err != nil {
		t.Error(err)
	}
	masterPublicKey := kgc1.GetSignMasterPublicKey()

	kgc2 := New()
	if kgc2 == nil {
		t.Error("kgc is nil")
	}

	uid2 := []byte("bob")
	hid2 := byte(0x01)
	userSignKey2, err := kgc2.GenerateUserSignKey(uid2, hid2)
	if err != nil {
		t.Error(err)
	}
	masterPublicKey2 := kgc2.GetSignMasterPublicKey()

	hashed := []byte("hello world")

	// alice sign
	sig, err := sm9.SignASN1(rand.Reader, userSignKey, hashed)
	if err != nil {
		t.Fatal(err)
	}

	// bob verify
	got := sm9.VerifyASN1(masterPublicKey, uid, hid, hashed, sig)
	if !got {
		t.Errorf("expected true, got false\n")
	}

	// bob sign
	sig, err = sm9.SignASN1(rand.Reader, userSignKey2, hashed)
	if err != nil {
		t.Fatal(err)
	}

	// alice verify
	got = sm9.VerifyASN1(masterPublicKey2, uid2, hid2, hashed, sig)
	if !got {
		t.Errorf("expected true, got false\n")
	}
}
