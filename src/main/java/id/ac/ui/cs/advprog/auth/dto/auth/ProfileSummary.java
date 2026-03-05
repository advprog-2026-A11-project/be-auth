package id.ac.ui.cs.advprog.auth.dto.auth;

public record ProfileSummary(
    Long id,
    String supabaseUserId,
    String username,
    String email,
    String displayName,
    String role,
    boolean active) {
}
