package id.ac.ui.cs.advprog.auth.dto.user;

import java.util.UUID;

public record UpdatePhoneResponse(
    String message,
    UUID userId,
    String phone) {
}
