package kgc

import (
	"crypto/rand"

	"github.com/emmansun/gmsm/sm9"
)

type Kgc struct {
	EncryptMasterKey *sm9.EncryptMasterPrivateKey
	SignMasterKey    *sm9.SignMasterPrivateKey
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
		EncryptMasterKey: encryptMasterKey,
		SignMasterKey:    signMasterKey,
	}
}

func (k *Kgc) GetSignMasterPublicKey() *sm9.SignMasterPublicKey {
	return k.SignMasterKey.Public()
}

func (k *Kgc) GenerateUserSignKey(uid []byte, hid byte) (*sm9.SignPrivateKey, error) {
	return k.SignMasterKey.GenerateUserKey(uid, hid)
}

func (k *Kgc) GetEncryptMasterPublicKey() *sm9.EncryptMasterPublicKey {
	return k.EncryptMasterKey.Public()
}

func (k *Kgc) GenerateUserEncryptKey(uid []byte, hid byte) (*sm9.EncryptPrivateKey, error) {
	return k.EncryptMasterKey.GenerateUserKey(uid, hid)
}
