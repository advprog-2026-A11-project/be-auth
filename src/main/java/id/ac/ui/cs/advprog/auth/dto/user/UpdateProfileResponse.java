package id.ac.ui.cs.advprog.auth.dto.user;

import java.util.UUID;

public record UpdateProfileResponse(
    String message,
    UUID userId,
    String username,
    String displayName,
    String email) {
}
