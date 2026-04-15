package id.ac.ui.cs.advprog.auth.dto.auth;

public record LoginResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    Long expiresIn,
    String userId,
    String role,
    String message) {
}
