package io.fusionauth.jwt.eddsa.provider;

import io.fusionauth.jwt.domain.KeyType;
import io.fusionauth.jwt.eddsa.EdDSA;
import io.fusionauth.jwt.spi.KeyTypeProvider;

public class EdDSAKeyTypeProvider implements KeyTypeProvider {
  @Override
  public KeyType get() {
    return EdDSA.KeyType;
  }
}
