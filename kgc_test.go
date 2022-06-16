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
