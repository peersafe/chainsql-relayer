/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
package tools

import (
	"errors"
	"fmt"

	"github.com/polynetwork/poly/common"
	"github.com/tjfoc/gmsm/x509"
)

type CertTrustChain struct {
	Certs []*x509.Certificate
}

func (set *CertTrustChain) Serialization(sink *common.ZeroCopySink) {
	sink.WriteUint16(uint16(len(set.Certs)))
	for _, v := range set.Certs {
		sink.WriteVarBytes(v.Raw)
	}
}

func (set *CertTrustChain) Deserialization(source *common.ZeroCopySource) (err error) {
	l, eof := source.NextUint16()
	if eof {
		return fmt.Errorf("failed to deserialize length")
	}
	set.Certs = make([]*x509.Certificate, l)
	for i := uint16(0); i < l; i++ {
		raw, eof := source.NextVarBytes()
		if eof {
			return fmt.Errorf("failed to get raw bytes for No.%d cert", i)
		}
		set.Certs[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("failed to parse cert for No.%d: %v", i, err)
		}
	}
	return nil
}

func (set *CertTrustChain) CheckSigWithRootCert(root *x509.Certificate, signed, sig []byte) error {
	for i, c := range set.Certs {
		if err := c.CheckSignatureFrom(root); err != nil {
			return fmt.Errorf("failed to check sig for No.%d cert from parent: %v", i, err)
		}
		root = c
	}
	if err := root.CheckSignature(root.SignatureAlgorithm, signed, sig); err != nil {
		return fmt.Errorf("failed to check the signature: %v", err)
	}
	return nil
}

func (set *CertTrustChain) CheckSig(signed, sig []byte) error {
	if len(set.Certs) < 1 {
		return errors.New("no cert in chain")
	}
	root := set.Certs[0]
	for i, c := range set.Certs[1:] {
		if err := c.CheckSignatureFrom(root); err != nil {
			return fmt.Errorf("failed to check sig for No.%d cert from parent: %v", i, err)
		}
		root = c
	}
	if err := root.CheckSignature(root.SignatureAlgorithm, signed, sig); err != nil {
		return fmt.Errorf("failed to check the signature: %v", err)
	}
	return nil
}
