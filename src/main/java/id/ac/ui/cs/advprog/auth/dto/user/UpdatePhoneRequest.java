package id.ac.ui.cs.advprog.auth.dto.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record UpdatePhoneRequest(
    @NotBlank(message = "phone is required")
    @Pattern(
        regexp = "^\\+?[0-9]{8,15}$",
        message = "phone must be a valid E.164-like number")
    String phone) {
}
