package id.ac.ui.cs.advprog.auth.dto.auth;

public record SsoCallbackResponse(
    String accessToken,
    String refreshToken,
    String userId,
    boolean linked,
    String message) {

  public static SsoCallbackResponse contractOnly() {
    return new SsoCallbackResponse(null, null, null, false,
        "SSO callback contract is ready. Implementation follows in next step.");
  }
}
