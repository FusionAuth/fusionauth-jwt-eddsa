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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;

import io.fusionauth.jwks.domain.JSONWebKey;
import io.fusionauth.jwt.BaseTest;
import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.jwt.json.Mapper;
import io.fusionauth.pem.domain.PEM;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * @author Daniel DeGroff
 */
public class JSONWebKeyParserTest extends BaseTest {
  @DataProvider(name = "ecPublicKeys")
  public Object[][] ecPublicKeys() {
    // X and Y coordinates from EC JSON Web Keys
    return new Object[][]{/*
        Alg     Crv      X, Y
        --------------------------------------------------------------------------------------------------------------*/
        {"P-256", "NIWpsIea0qzB22S0utDG8dGFYqEInv9C7ZgZuKtwjno", "iVFFtTgiInz_fjh-n1YqbibnUb2vtBZFs3wPpQw3mc0"},
        {"P-384", "z6kxnA_HZP8t9F9XBH-YYggdQi4FrcuhSElu0mxcRITIuJG7YgtSWYUmBHNv9J0-", "uDShjOHRepB5ll8B8Cs-A4kxbs8cl-PfE0gAtqE72Cdhbb5ZPNclrzi6rSfx1TuU"},
        {"P-521", "AASKtNZn-wSH5gPokx0SR2R9rpv8Gzf8pmSUJ8dBvrsSLSL-nSMtQC5lsmgTKpyd8p3WZFkn3BkUgYPrNxrR8Wcy", "AehbMYfcRK8RfeHG2XHyWM0PuEVWcKB35NwXhce9meNyjsgJAZPBaCfR9FqDZrPCc4ARpw9UNmlYsZ-j3wHmxu-M"}
    };
  }

  @Test
  public void parse_ec_certificates() throws Exception {
    // Just parsing, expecting no explosions.

    // EC 256 Certificate
    byte[] certificate256 = Files.readAllBytes(Paths.get("src/test/resources/jwk/ec_certificate_p_256.json"));
    JSONWebKey.parse(Mapper.deserialize(certificate256, JSONWebKey.class));

    // EC 384 Certificate
    byte[] certificate384 = Files.readAllBytes(Paths.get("src/test/resources/jwk/ec_certificate_p_384.json"));
    JSONWebKey.parse(Mapper.deserialize(certificate384, JSONWebKey.class));

    // EC 521 Certificate
    byte[] certificate521 = Files.readAllBytes(Paths.get("src/test/resources/jwk/ec_certificate_p_521.json"));
    JSONWebKey.parse(Mapper.deserialize(certificate521, JSONWebKey.class));

    // Hacked public key
    byte[] hacked256 = Files.readAllBytes(Paths.get("src/test/resources/jwk/ec_certificate_hacked_x5c_p_256.json"));
    try {
      JSONWebKey.parse(Mapper.deserialize(hacked256, JSONWebKey.class));
      fail("Expected an exception");
    } catch (JSONWebKeyParserException expected) {
      assertEquals(expected.getMessage(),
                   "Expected an x coordinate value of [92281275340165409471170845681463968816032370456437802964396339248939820362156] but found [114355049275855008944383887078211226358178801567209304915100916863237914171390].  The certificate found in [x5c] does not match the [x] coordinate property.");
    }
  }

  @Test(dataProvider = "ecPublicKeys")
  public void parse_ec_keys(String curve, String x, String y) {
    JSONWebKey expected = new JSONWebKey();
    expected.crv = curve;
    expected.kty = KeyType.EC;
    expected.x = x;
    expected.y = y;

    PublicKey publicKey = JSONWebKey.parse(expected);
    assertNotNull(publicKey);

    // Compare to the original expected key
    String encodedPEM = PEM.encode(publicKey);
    assertEquals(JSONWebKey.build(encodedPEM).x, expected.x);
    assertEquals(JSONWebKey.build(encodedPEM).y, expected.y);

    // Get the public key from the PEM, and assert against the expected values
    PEM pem = PEM.decode(encodedPEM);
    assertEquals(JSONWebKey.build(pem.publicKey).x, expected.x);
    assertEquals(JSONWebKey.build(pem.publicKey).y, expected.y);
  }
}
