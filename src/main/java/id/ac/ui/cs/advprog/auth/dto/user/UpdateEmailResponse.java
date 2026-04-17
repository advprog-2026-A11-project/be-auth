package id.ac.ui.cs.advprog.auth.dto.user;

import java.util.UUID;

public record UpdateEmailResponse(
    String message,
    UUID userId,
    String email) {
}
