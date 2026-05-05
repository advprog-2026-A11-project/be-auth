package id.ac.ui.cs.advprog.auth.security;

public record AuthenticatedUserPrincipal(
    String sub,
    String email,
    String role,
    String publicUserId) {
}

