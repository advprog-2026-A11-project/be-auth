package id.ac.ui.cs.advprog.auth.dto.auth;

public record SsoCallbackResponse(
    String accessToken,
    String refreshToken,
    String userId,
    boolean linked,
    String message) {
}
