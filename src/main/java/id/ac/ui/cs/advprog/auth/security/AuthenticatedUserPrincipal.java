package id.ac.ui.cs.advprog.auth.security;

public record AuthenticatedUserPrincipal(
    String sub,
    String email,
    String role,
    String publicUserId) {

  public AuthenticatedUserPrincipal(String sub, String email, String role) {
    this(sub, email, role, null);
  }
}
