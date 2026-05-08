package id.ac.ui.cs.advprog.auth.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "revoked_access_tokens")
public class RevokedAccessToken {

  @Id
  @Column(nullable = false, updatable = false, length = 64)
  private String tokenHash;

  @Column(nullable = false)
  private Instant expiresAt;

  protected RevokedAccessToken() {
  }

  public RevokedAccessToken(String tokenHash, Instant expiresAt) {
    this.tokenHash = tokenHash;
    this.expiresAt = expiresAt;
  }

  public String getTokenHash() {
    return tokenHash;
  }

  public Instant getExpiresAt() {
    return expiresAt;
  }
}

