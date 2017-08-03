package utils

import (
	"encoding/base64"
	"crypto/sha256"
	"github.com/golang/protobuf/proto"
	"crypto"
	"crypto/rsa"
	"crypto/rand"
)

func Hash(pb proto.Message) []byte {
	bytes, _ := proto.Marshal(pb)
	h := sha256.New()
	h.Write(bytes)
	b := h.Sum(nil)
	return b
}

func Hash64(pb proto.Message) string {
	return base64.URLEncoding.EncodeToString(Hash(pb))
}

func SignMessage(pb proto.Message, secret *rsa.PrivateKey) (string, error)  {
	return Sign(Hash(pb), secret)
}

func VerifyMessage(pb proto.Message, signature string, key *rsa.PublicKey) error {
	bytes, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	return Verify(Hash(pb), bytes, key)
}

func Sign(digest []byte, secret *rsa.PrivateKey) (string, error)  {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	signature, err := rsa.SignPSS(rand.Reader, secret, crypto.SHA256, digest, &opts)
	return base64.URLEncoding.EncodeToString(signature), err;
}

func Verify(hashed []byte, signature []byte, key *rsa.PublicKey) error {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	return rsa.VerifyPSS(key, crypto.SHA256, hashed, signature, &opts)
}
