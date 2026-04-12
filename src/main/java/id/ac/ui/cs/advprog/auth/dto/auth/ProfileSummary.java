package id.ac.ui.cs.advprog.auth.dto.auth;

import java.util.UUID;

public record ProfileSummary(
    UUID id,
    String supabaseUserId,
    String username,
    String email,
    String displayName,
    String role,
    boolean active) {
}
