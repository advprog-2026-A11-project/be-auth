package id.ac.ui.cs.advprog.auth.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "google_sso_pkce_states")
public class GoogleSsoPkceState {

  @Id
  @Column(nullable = false, updatable = false)
  private String flowId;

  @Column(nullable = false)
  private String codeVerifier;

  @Column(nullable = false)
  private Instant expiresAt;

  @Column(nullable = false, length = 1000)
  private String redirectUrl;

  protected GoogleSsoPkceState() {
  }

  public GoogleSsoPkceState(
      String flowId,
      String codeVerifier,
      Instant expiresAt,
      String redirectUrl) {
    this.flowId = flowId;
    this.codeVerifier = codeVerifier;
    this.expiresAt = expiresAt;
    this.redirectUrl = redirectUrl;
  }

  public String getFlowId() {
    return flowId;
  }

  public String getCodeVerifier() {
    return codeVerifier;
  }

  public Instant getExpiresAt() {
    return expiresAt;
  }

  public String getRedirectUrl() {
    return redirectUrl;
  }
}
