package io.fusionauth.jwt.eddsa.provider;

import io.fusionauth.jwt.domain.Algorithm;
import io.fusionauth.jwt.eddsa.EdDSA;
import io.fusionauth.jwt.spi.AlgorithmProvider;

public class EdDSAAlgorithmProvider implements AlgorithmProvider {
  @Override
  public Algorithm get() {
    return EdDSA.Algorithm;
  }
}
