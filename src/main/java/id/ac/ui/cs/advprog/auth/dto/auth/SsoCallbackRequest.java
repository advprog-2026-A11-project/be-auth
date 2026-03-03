package id.ac.ui.cs.advprog.auth.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record SsoCallbackRequest(
    @NotBlank(message = "code is required")
    String code,
    @NotBlank(message = "state is required")
    String state) {
}
