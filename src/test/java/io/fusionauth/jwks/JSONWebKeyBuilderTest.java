/*
 * Copyright (c) 2018-2019, FusionAuth, All Rights Reserved
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

package io.fusionauth.jwks;

import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.BaseTest;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.Test;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeyBuilderTest extends BaseTest {
  @Test
  public void eddsa_private() throws Exception {
    // EdDSA 256 Private key - PKCS#8 encapsulated already
    EdECPrivateKey key = PEM.decode(Paths.get("src/test/resources/ed_dsa_ed25519_private_key.pem")).getPrivateKey();
    assertJSONEquals(JSONWebKey.build(key), "src/test/resources/jwk/ed_dsa_ed25519_private_key.json");
  }

  @Test
  public void eddsa_public() throws Exception {
    // ed25519
    EdECPublicKey publicKey = PEM.decode(Paths.get("src/test/resources/ed_dsa_ed25519_public_key.pem")).getPublicKey();
    assertJSONEquals(JSONWebKey.build(publicKey), "src/test/resources/jwk/ed_dsa_ed25519_public_key.json");

    // EC 256 Certificate
    Certificate certificate = PEM.decode(Paths.get("src/test/resources/ec_certificate_p_256.pem")).getCertificate();
    assertJSONEquals(JSONWebKey.build(certificate), "src/test/resources/jwk/ec_certificate_p_256.json");
  }
}
