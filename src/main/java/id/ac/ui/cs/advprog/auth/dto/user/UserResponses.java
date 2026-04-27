package id.ac.ui.cs.advprog.auth.dto.user;

import java.util.UUID;

public final class UserResponses {

  private UserResponses() {
  }

  public record DeleteAccountResponse(
      String message,
      UUID userId) {
  }

  public record UpdateEmailResponse(
      String message,
      UUID userId,
      String email) {
  }

  public record UpdatePhoneResponse(
      String message,
      UUID userId,
      String phone) {
  }

  public record UpdateProfileResponse(
      String message,
      UUID userId,
      String username,
      String displayName,
      String email) {
  }
}
