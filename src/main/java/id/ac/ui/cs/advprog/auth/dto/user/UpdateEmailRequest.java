package id.ac.ui.cs.advprog.auth.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UpdateEmailRequest(
    @NotBlank(message = "email is required")
    @Email(message = "email must be valid")
    String email) {
}
