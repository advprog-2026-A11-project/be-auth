package id.ac.ui.cs.advprog.auth.dto.user;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.time.LocalDateTime;

public record UserProfileResponse(
    Long id,
    String username,
    String email,
    String supabaseUserId,
    String displayName,
    String role,
    boolean isActive,
    LocalDateTime createdAt,
    LocalDateTime updatedAt) {

  public static UserProfileResponse from(UserProfile user) {
    return new UserProfileResponse(
        user.getId(),
        user.getUsername(),
        user.getEmail(),
        user.getSupabaseUserId(),
        user.getDisplayName(),
        user.getRole(),
        user.isActive(),
        user.getCreatedAt(),
        user.getUpdatedAt());
  }
}
