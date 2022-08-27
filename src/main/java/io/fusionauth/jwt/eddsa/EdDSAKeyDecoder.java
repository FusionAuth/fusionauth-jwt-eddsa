/*
 * Copyright (c) 2022, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package io.fusionauth.jwt.eddsa;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import io.fusionauth.der.DerInputStream;
import io.fusionauth.der.DerValue;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.pem.KeyDecoder;
import io.fusionauth.pem.domain.PEM;

/**
 * @author Daniel DeGroff
 */
public class EdDSAKeyDecoder implements KeyDecoder {
  @Override
  public PEM decode(PrivateKey privateKey, DerValue[] sequence) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    //
    // Inpput: MC4CAQAwBQYDK2VwBCIEIIJtJBnTuKbIy5YjoNiH95ky3DcA3kRB0I2i7DkVM6Cf
    //   -> https://lapo.it/asn1js/#MC4CAQAwBQYDK2VwBCIEIIJtJBnTuKbIy5YjoNiH95ky3DcA3kRB0I2i7DkVM6Cf

    // No public key:
    //
    // SEQUENCE (3 elem)
    //   INTEGER 0
    //   SEQUENCE (1 elem)
    //     OBJECT IDENTIFIER 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
    //   OCTET STRING (34 byte) 0420826D2419D3B8A6C8CB9623A0D887F79932DC3700DE4441D08DA2EC391533A09F
    //     OCTET STRING (32 byte) 826D2419D3B8A6C8CB9623A0D887F79932DC3700DE4441D08DA2EC391533A09F
    //

    // https://www.rfc-editor.org/rfc/rfc8410
    // https://www.rfc-editor.org/rfc/rfc8410#section-10.3

    //    SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //       algorithm         AlgorithmIdentifier,
    //       subjectPublicKey  BIT STRING
    //   }

    if (sequence.length == 3 && sequence[2].tag.rawByte == (byte) 0xA1) {
      System.out.println("here");
      byte[] octetString = sequence[2].toByteArray();
      DerValue[] privateKeySequence = new DerInputStream(new DerInputStream(sequence[2].toByteArray()).toByteArray()).getSequence();
//    if (privateKeySequence.length == 3 && privateKeySequence[2].tag.rawByte == (byte) 0xA1) {
      DerValue bitString = new DerInputStream(octetString).readDerValue();
      byte[] encodedPublicKey = getEncodedPublicKeyFromPrivate(bitString, privateKey.getEncoded());
      PublicKey publicKey = KeyFactory.getInstance(EdDSA.KeyType.algorithm).generatePublic(new X509EncodedKeySpec(encodedPublicKey));
      return new PEM(privateKey, publicKey);
    } else {
      // The private key did not contain the public key
      return new PEM(privateKey);
    }
  }

  @Override
  public PEM decode(String encoded) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    return null;
  }

  @Override
  public KeyType keyType() {
    return EdDSA.KeyType;
  }
}
