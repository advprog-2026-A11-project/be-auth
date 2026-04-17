package id.ac.ui.cs.advprog.auth.dto.auth;

public record SsoUrlResponse(
    String provider,
    String authorizationUrl,
    String message) {
}
