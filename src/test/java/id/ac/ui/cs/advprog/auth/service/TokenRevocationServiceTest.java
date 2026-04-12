package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class TokenRevocationServiceTest {

  private final TokenRevocationService service = new TokenRevocationService();

  @Test
  void revokeIgnoresBlankToken() {
    service.revoke(" ", Instant.now().plusSeconds(60));

    assertFalse(service.isRevoked(" "));
  }

  @Test
  void revokeIgnoresNullExpiry() {
    service.revoke("access-token", null);

    assertFalse(service.isRevoked("access-token"));
  }

  @Test
  void isRevokedReturnsFalseForBlankToken() {
    assertFalse(service.isRevoked(" "));
  }

  @Test
  void isRevokedReturnsTrueForActiveRevokedToken() {
    service.revoke("access-token", Instant.now().plusSeconds(60));

    assertTrue(service.isRevoked("access-token"));
  }

  @Test
  void isRevokedCleansUpExpiredToken() {
    service.revoke("expired-token", Instant.now().minusSeconds(60));

    assertFalse(service.isRevoked("expired-token"));
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
    }
  }
}
