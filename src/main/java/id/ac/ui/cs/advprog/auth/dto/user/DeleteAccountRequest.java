package id.ac.ui.cs.advprog.auth.dto.user;

import jakarta.validation.constraints.NotBlank;

public record DeleteAccountRequest(
    @NotBlank(message = "confirmation is required")
    String confirmation) {
}
