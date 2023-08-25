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

import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.domain.KeyType;

/**
 * EdDSA, Edwards-Curve Digital Signature Algorithm
 * OID: 1.3.101.112
 *
 * @author Daniel DeGroff
 */
public class EdDSA {
  public static Algorithm Algorithm = new Algorithm("EdDSA", "EdDSA");

  public static KeyType KeyType = new KeyType("OKP", "EdDSA", "1.3.101.112");

  private EdDSA() {
  }
}
