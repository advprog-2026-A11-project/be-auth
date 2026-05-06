package id.ac.ui.cs.advprog.auth.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class AuthStateModelTest {

  @Test
  void revokedAccessTokenExposesConstructorValues() {
    Instant expiresAt = Instant.parse("2026-05-03T00:10:00Z");

    RevokedAccessToken token = new RevokedAccessToken("token-hash", expiresAt);

    assertEquals("token-hash", token.getTokenHash());
    assertEquals(expiresAt, token.getExpiresAt());
  }
}

