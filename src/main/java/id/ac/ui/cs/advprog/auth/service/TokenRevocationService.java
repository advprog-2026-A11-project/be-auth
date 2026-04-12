package id.ac.ui.cs.advprog.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class TokenRevocationService {

  private final Map<String, Instant> revokedTokens = new ConcurrentHashMap<>();

  public void revoke(String accessToken, Instant expiresAt) {
    if (!StringUtils.hasText(accessToken) || expiresAt == null) {
      return;
    }

    cleanupExpired();
    revokedTokens.put(hash(accessToken), expiresAt);
  }

  public boolean isRevoked(String accessToken) {
    if (!StringUtils.hasText(accessToken)) {
      return false;
    }

    cleanupExpired();
    Instant expiresAt = revokedTokens.get(hash(accessToken));
    return expiresAt != null && expiresAt.isAfter(Instant.now());
  }

  private void cleanupExpired() {
    Instant now = Instant.now();
    revokedTokens.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
  }

  private String hash(String accessToken) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hash);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 algorithm not available", ex);
    }
  }
}
