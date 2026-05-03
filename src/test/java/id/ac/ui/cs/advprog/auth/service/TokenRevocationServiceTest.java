package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class TokenRevocationServiceTest {

  private final RevokedTokenStore revokedTokenStore = Mockito.mock(RevokedTokenStore.class);
  private final Clock clock = Clock.fixed(Instant.parse("2026-05-03T00:00:00Z"), ZoneOffset.UTC);
  private final TokenRevocationService service = new TokenRevocationService(revokedTokenStore, clock);

  @Test
  void revokeIgnoresBlankToken() {
    service.revoke(" ", Instant.now().plusSeconds(60));

    assertFalse(service.isRevoked(" "));
    verify(revokedTokenStore, never()).save(any(), any(), any());
  }

  @Test
  void revokeIgnoresNullExpiry() {
    service.revoke("access-token", null);

    assertFalse(service.isRevoked("access-token"));
    verify(revokedTokenStore, never()).save(any(), any(), any());
  }

  @Test
  void isRevokedReturnsFalseForBlankToken() {
    assertFalse(service.isRevoked(" "));
    verify(revokedTokenStore, never()).exists(any(), any());
  }

  @Test
  void isRevokedReturnsTrueForActiveRevokedToken() {
    when(revokedTokenStore.exists(
        "3f16bed7089f4653e5ef21bfd2824d7f3aaaecc7a598e7e89c580e1606a9cc52",
        Instant.parse("2026-05-03T00:00:00Z"))).thenReturn(true);

    assertTrue(service.isRevoked("access-token"));
  }

  @Test
  void isRevokedCleansUpExpiredToken() {
    when(revokedTokenStore.exists(any(), any())).thenReturn(false);

    assertFalse(service.isRevoked("expired-token"));
    verify(revokedTokenStore).exists(
        "b52b3ef2233858ce1156d85f235cf2c41eddfa8ca1eedc924398b9af1db303cb",
        Instant.parse("2026-05-03T00:00:00Z"));
  }

  @Test
  void revokeHashesTokenBeforeSaving() {
    Instant expiresAt = Instant.parse("2026-05-03T00:10:00Z");

    service.revoke("access-token", expiresAt);

    verify(revokedTokenStore).save(
        "3f16bed7089f4653e5ef21bfd2824d7f3aaaecc7a598e7e89c580e1606a9cc52",
        expiresAt,
        Instant.parse("2026-05-03T00:00:00Z"));
  }

  @Test
  void revokeThrowsWhenSha256AlgorithmIsUnavailable() throws Exception {
    try (MockedStatic<MessageDigest> messageDigest = mockStatic(MessageDigest.class)) {
      messageDigest.when(() -> MessageDigest.getInstance("SHA-256"))
          .thenThrow(new NoSuchAlgorithmException("missing"));

      IllegalStateException ex = assertThrows(
          IllegalStateException.class,
          () -> service.revoke("access-token", Instant.now().plusSeconds(60)));

      assertTrue(ex.getMessage().contains("SHA-256 algorithm not available"));
      verify(revokedTokenStore, never()).save(any(), any(), any());
    }
  }
}
