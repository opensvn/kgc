package kgc

import "testing"

func TestNewKgc(t *testing.T) {
	kgc := New()
	if kgc == nil {
		t.Error("kgc is nil")
	}

	if kgc.encryptMasterKey == nil {
		t.Error("kgc.encryptMasterKey is nil")
	}

	if kgc.signMasterKey == nil {
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
