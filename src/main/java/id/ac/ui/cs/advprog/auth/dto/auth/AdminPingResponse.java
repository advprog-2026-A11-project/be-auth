package id.ac.ui.cs.advprog.auth.dto.auth;

import java.util.UUID;

public record AdminPingResponse(
    String message,
    UUID userId) {
}
