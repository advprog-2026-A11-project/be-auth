package id.ac.ui.cs.advprog.auth.dto.auth;

public record SsoUrlResponse(
    String provider,
    String authorizationUrl,
    String message) {

  public static SsoUrlResponse contractOnly(String provider) {
    return new SsoUrlResponse(provider, null,
        "SSO URL contract is ready. Implementation follows in next step.");
  }
}
