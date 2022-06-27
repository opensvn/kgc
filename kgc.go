package kgc

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/sm9"
	"github.com/emmansun/gmsm/sm9/bn256"
)

type Kgc struct {
	EncryptMasterKey *sm9.EncryptMasterPrivateKey
	SignMasterKey    *sm9.SignMasterPrivateKey
}

func New() (*Kgc, error) {
	encryptMasterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	signMasterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Kgc{
		EncryptMasterKey: encryptMasterKey,
		SignMasterKey:    signMasterKey,
	}, nil
}

func Load(hexEncryptKey, hexSignKey string) (*Kgc, error) {
	encryptMasterPriKey, err := LoadEncryptMasterPrivateKey(hexEncryptKey)
	if err != nil {
		return nil, err
	}

	signMasterPriKey, err := LoadSignMasterPrivateKey(hexSignKey)
	if err != nil {
		return nil, err
	}

	return &Kgc{
		EncryptMasterKey: encryptMasterPriKey,
		SignMasterKey:    signMasterPriKey,
	}, nil
}

func LoadEncryptMasterPrivateKey(hexEncryptKey string) (*sm9.EncryptMasterPrivateKey, error) {
	big, err := bigFromHex(hexEncryptKey)
	if err != nil {
		return nil, err
	}

	masterKey := new(sm9.EncryptMasterPrivateKey)
	masterKey.D = big
	masterKey.MasterPublicKey = new(bn256.G1).ScalarBaseMult(masterKey.D)

	return masterKey, nil
}

func LoadSignMasterPrivateKey(hexSignKey string) (*sm9.SignMasterPrivateKey, error) {
	big, err := bigFromHex(hexSignKey)
	if err != nil {
		return nil, err
	}

	masterKey := new(sm9.SignMasterPrivateKey)
	masterKey.D = big
	masterKey.MasterPublicKey = new(bn256.G2).ScalarBaseMult(masterKey.D)

	return masterKey, nil
}

func bigFromHex(hex string) (*big.Int, error) {
	b, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		return nil, errors.New("invalid hex string")
	}
	return b, nil
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
