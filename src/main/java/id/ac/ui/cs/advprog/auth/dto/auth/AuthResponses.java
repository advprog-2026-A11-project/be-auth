package id.ac.ui.cs.advprog.auth.dto.auth;

import java.util.UUID;

public final class AuthResponses {

  private AuthResponses() {
  }

  public record AdminPingResponse(
      String message,
      UUID userId) {
  }

  public record LoginResponse(
      String accessToken,
      String refreshToken,
      String tokenType,
      Long expiresIn,
      String userId,
      String role,
      String message) {
  }

  public record LogoutResponse(String message) {
  }

  public record MessageResponse(String message) {
  }

  public record SsoCallbackResponse(
      String accessToken,
      String refreshToken,
      String userId,
      boolean linked,
      String message) {
  }

  public record SsoUrlResponse(
      String provider,
      String authorizationUrl,
      String message) {
  }
}

