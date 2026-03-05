package id.ac.ui.cs.advprog.auth.dto.auth;

public record LoginResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    Long expiresIn,
    String userId,
    String role,
    String message) {

  public static LoginResponse contractOnly() {
    return new LoginResponse(null, null, "Bearer", null, null, null,
        "Login contract is ready. Implementation follows in next step.");
  }
}
