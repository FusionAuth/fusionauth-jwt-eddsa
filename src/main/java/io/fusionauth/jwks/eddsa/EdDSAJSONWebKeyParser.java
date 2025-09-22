/*
 * Copyright (c) 2023, FusionAuth, All Rights Reserved
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
package io.fusionauth.jwks.eddsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

import io.fusionauth.jwks.JSONWebKeyParser;
import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.jwt.eddsa.EdDSA;
import static io.fusionauth.jwks.JWKUtils.base64DecodeUint;

/**
 * @author Daniel DeGroff
 */
public class EdDSAJSONWebKeyParser implements JSONWebKeyParser {
  @Override
  public KeyType keyType() {
    return EdDSA.KeyType;
  }

  @Override
  public PublicKey parse(JSONWebKey key) {
    try {
      BigInteger modulus = base64DecodeUint(key.n);
      BigInteger publicExponent = base64DecodeUint(key.e);
      PublicKey publicKey = KeyFactory.getInstance(EdDSA.KeyType.algorithm)
                                      .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

      // If an x5c is found in the key, verify the public key
      if (key.x5c != null && !key.x5c.isEmpty()) {
//        verifyX5cRSA(key, modulus, publicExponent);
      }

      return publicKey;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
