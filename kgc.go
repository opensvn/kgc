package kgc

import (
	"crypto/rand"

	"github.com/emmansun/gmsm/sm9"
)

type Kgc struct {
	encryptMasterKey *sm9.EncryptMasterPrivateKey
	signMasterKey    *sm9.SignMasterPrivateKey
}

func New() *Kgc {
	encryptMasterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		return nil
	}

	signMasterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		return nil
	}

	return &Kgc{
		encryptMasterKey: encryptMasterKey,
		signMasterKey:    signMasterKey,
	}
}

func (k *Kgc) GenerateUserSignKey(uid []byte, hid byte) (*sm9.SignPrivateKey, error) {
	return k.signMasterKey.GenerateUserKey(uid, hid)
}

func (k *Kgc) GenerateUserEncryptKey(uid []byte, hid byte) (*sm9.EncryptPrivateKey, error) {
	return k.encryptMasterKey.GenerateUserKey(uid, hid)
}
