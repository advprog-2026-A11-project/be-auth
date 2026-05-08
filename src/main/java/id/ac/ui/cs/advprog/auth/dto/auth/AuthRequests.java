package id.ac.ui.cs.advprog.auth.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class AuthRequests {

  private AuthRequests() {
  }

  public record ChangePasswordRequest(
      String currentPassword,
      @NotBlank(message = "newPassword is required")
      @Size(min = 8, message = "newPassword must be at least 8 characters")
      String newPassword) {
  }

  public record LoginRequest(
      @NotBlank(message = "identifier is required")
      String identifier,
      @NotBlank(message = "password is required")
      String password) {
  }

  public record RefreshTokenRequest(
      @NotBlank(message = "refreshToken is required")
      String refreshToken) {
  }

  public record RegisterRequest(
      @NotBlank(message = "email is required")
      @Email(message = "email must be valid")
      String email,
      @NotBlank(message = "phone is required")
      @Pattern(
          regexp = "^(?=(?:\\D*\\d){8,15}\\D*$)\\+?[0-9][0-9\\s\\-()]*$",
          message = "phone must contain 8-15 digits")
      String phone,
      @NotBlank(message = "password is required")
      @Size(min = 8, message = "password must be at least 8 characters")
      String password,
      @Size(min = 3, max = 30, message = "username must be 3-30 characters")
      String username,
      @Size(max = 100, message = "displayName must be <= 100 characters")
      String displayName) {
  }
}

