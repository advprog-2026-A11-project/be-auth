package id.ac.ui.cs.advprog.auth.dto.user;

import jakarta.validation.constraints.Size;

public record UpdateProfileRequest(
    @Size(min = 3, max = 30, message = "username must be 3-30 characters")
    String username,
    @Size(max = 100, message = "displayName must be <= 100 characters")
    String displayName) {
}
