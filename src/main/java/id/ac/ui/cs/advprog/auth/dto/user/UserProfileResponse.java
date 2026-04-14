package id.ac.ui.cs.advprog.auth.dto.user;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.RoleMapper;
import java.time.LocalDateTime;
import java.util.UUID;

public record UserProfileResponse(
    UUID id,
    String username,
    String email,
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
        user.getDisplayName(),
        RoleMapper.canonicalize(user.getRole()),
        user.isActive(),
        user.getCreatedAt(),
        user.getUpdatedAt());
  }
}
