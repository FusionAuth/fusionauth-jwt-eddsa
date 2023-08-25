package io.fusionauth.jwt.eddsa.provider;

import io.fusionauth.jwt.eddsa.EdDSAKeyDecoder;
import io.fusionauth.jwt.spi.KeyDecoderProvider;
import io.fusionauth.pem.KeyDecoder;

public class EdDSAKeyDecoderProvider implements KeyDecoderProvider {
  @Override
  public KeyDecoder get() {
    return new EdDSAKeyDecoder();
  }
}
