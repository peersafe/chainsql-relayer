package test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/polynetwork/chainsql-relayer/tools"
	"github.com/polynetwork/poly/common"
	"github.com/tjfoc/gmsm/pkcs12"
	sm2 "github.com/tjfoc/gmsm/sm2"
)

func TestSignature(t *testing.T) {
	caSet := &tools.CertTrustChain{
		Certs: make([]*sm2.Certificate, 2),
	}
	keysCa, err := ioutil.ReadFile("../bin/certs/rootCA.crt")
	if err != nil {
		t.Errorf("TestSignature - read rootCA: %s", err.Error())
	}

	blkAgency, _ := pem.Decode(keysCa)
	caSet.Certs[0], err = sm2.ParseCertificate(blkAgency.Bytes)
	if err != nil {
		t.Errorf("TestSignature - ParseCertificate: %s", err.Error())
	}
	keysCert, err := ioutil.ReadFile("../bin/certs/server.crt")
	if err != nil {
		t.Errorf("TestSignature - read server.crt: %s", err.Error())
	}

	blk, _ := pem.Decode(keysCert)
	caSet.Certs[1], err = sm2.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Errorf("TestSignature - ParseCertificate: %s", err.Error())
	}

	keys, err := ioutil.ReadFile("../bin/certs/pkcs8.server.key")
	if err != nil {
		t.Errorf("TestSignature: %s", err.Error())
	}

	sink := common.NewZeroCopySink(nil)
	caSet.Serialization(sink)

	rawInfo := "peersafe"

	blk, _ = pem.Decode(keys)
	var sig []byte
	hasher := sm2.SHA256.New()
	hasher.Write([]byte(rawInfo))
	raw := hasher.Sum(nil)
	key, err := pkcs12.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Errorf("TestSignature - ParsePKCS8PrivateKey: %s", err.Error())
	}
	priv := key.(*ecdsa.PrivateKey)
	sig, err = priv.Sign(rand.Reader, raw, nil)
	if err != nil {
		t.Errorf("TestSignature - sig: %s", err.Error())
	}
	caSet.Certs[0].SignatureAlgorithm = sm2.SHA256WithRSA
	err = caSet.CheckSigWithRootCert(caSet.Certs[0], []byte(rawInfo), sig)
	if err != nil {
		t.Errorf("TestSignature - CheckSigWithRootCert: %s", err.Error())
	}
}
