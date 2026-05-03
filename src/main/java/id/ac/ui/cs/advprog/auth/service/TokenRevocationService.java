package id.ac.ui.cs.advprog.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class TokenRevocationService {

  private final RevokedTokenStore revokedTokenStore;
  private final Clock clock;

  public TokenRevocationService(RevokedTokenStore revokedTokenStore, Clock clock) {
    this.revokedTokenStore = revokedTokenStore;
    this.clock = clock;
  }

  public void revoke(String accessToken, Instant expiresAt) {
    if (!StringUtils.hasText(accessToken) || expiresAt == null) {
      return;
    }

    revokedTokenStore.save(hash(accessToken), expiresAt, Instant.now(clock));
  }

  public boolean isRevoked(String accessToken) {
    if (!StringUtils.hasText(accessToken)) {
      return false;
    }

    return revokedTokenStore.exists(hash(accessToken), Instant.now(clock));
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
