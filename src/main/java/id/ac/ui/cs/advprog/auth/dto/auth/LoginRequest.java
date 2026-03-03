package id.ac.ui.cs.advprog.auth.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
    @NotBlank(message = "identifier is required")
    String identifier,
    @NotBlank(message = "password is required")
    String password) {
}
