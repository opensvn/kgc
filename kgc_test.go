package kgc

import "testing"

func TestNewKgc(t *testing.T) {
	kgc := New()
	if kgc == nil {
		t.Error("kgc is nil")
	}
}
