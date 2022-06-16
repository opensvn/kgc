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
