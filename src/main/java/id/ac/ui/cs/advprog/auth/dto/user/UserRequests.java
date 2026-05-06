package id.ac.ui.cs.advprog.auth.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class UserRequests {

  private UserRequests() {
  }

  public record DeleteAccountRequest(
      @NotBlank(message = "confirmation is required")
      String confirmation) {
  }

  public record UpdateEmailRequest(
      @NotBlank(message = "email is required")
      @Email(message = "email must be valid")
      String email) {
  }

  public record UpdatePhoneRequest(
      @NotBlank(message = "phone is required")
      @Pattern(
          regexp = "^\\+?[0-9]{8,15}$",
          message = "phone must be a valid E.164-like number")
      String phone) {
  }

  public record UpdateProfileRequest(
      @Size(min = 3, max = 30, message = "username must be 3-30 characters")
      String username,
      @Size(max = 100, message = "displayName must be <= 100 characters")
      String displayName) {
  }
}

