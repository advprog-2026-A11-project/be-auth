package id.ac.ui.cs.advprog.auth.dto.auth;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.RoleMapper;
import java.time.Instant;
import java.util.List;

public record AuthMeResponse(
    String sub,
    List<String> aud,
    Object iss,
    Instant exp,
    Profile profile) {

  public static AuthMeResponse of(
      String sub,
      List<String> aud,
      Object iss,
      Instant exp,
      UserProfile user) {
    if (user == null) {
      return new AuthMeResponse(sub, aud, iss, exp, null);
    }

    return new AuthMeResponse(
        sub,
        aud,
        iss,
        exp,
        new Profile(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.getPhone(),
            user.getDisplayName(),
            RoleMapper.canonicalize(user.getRole()),
            user.getAuthProvider(),
            user.getGoogleSub(),
            user.isActive()));
  }

  public record Profile(
      java.util.UUID id,
      String username,
      String email,
      String phone,
      String displayName,
      String role,
      String authProvider,
      String googleSub,
      boolean isActive) {
  }
}
