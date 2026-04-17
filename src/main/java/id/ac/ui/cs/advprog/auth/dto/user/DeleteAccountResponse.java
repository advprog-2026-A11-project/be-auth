package id.ac.ui.cs.advprog.auth.dto.user;

import java.util.UUID;

public record DeleteAccountResponse(
    String message,
    UUID userId) {
}
