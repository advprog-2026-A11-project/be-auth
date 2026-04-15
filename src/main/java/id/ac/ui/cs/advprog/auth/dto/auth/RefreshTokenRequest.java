package id.ac.ui.cs.advprog.auth.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(
    @NotBlank(message = "refreshToken is required")
    String refreshToken) {
}
