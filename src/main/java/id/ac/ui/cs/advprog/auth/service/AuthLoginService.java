package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class AuthLoginService {

  private final SupabaseAuthClient supabaseAuthClient;
  private final UserProfileService userProfileService;

  public AuthLoginService(
      SupabaseAuthClient supabaseAuthClient,
      UserProfileService userProfileService) {
    this.supabaseAuthClient = supabaseAuthClient;
    this.userProfileService = userProfileService;
  }

  public LoginResponse login(String identifier, String password) {
    String email = resolveEmailIdentifier(identifier);
    SupabaseAuthClient.LoginResult result = supabaseAuthClient.loginWithPassword(email, password);

    UserProfile profile = userProfileService.upsertFromIdentity(
        result.supabaseUserId(),
        result.email(),
        result.role());

    return new LoginResponse(
        result.accessToken(),
        result.refreshToken(),
        "Bearer",
        result.expiresIn(),
        profile.getSupabaseUserId(),
        profile.getRole(),
        "Login successful");
  }

  private String resolveEmailIdentifier(String identifier) {
    if (!StringUtils.hasText(identifier)) {
      throw new IllegalArgumentException("identifier is required");
    }

    String normalized = identifier.trim();
    if (normalized.contains("@")) {
      return normalized;
    }

    Optional<UserProfile> byUsername = userProfileService.findByUsername(normalized);
    if (byUsername.isPresent() && StringUtils.hasText(byUsername.get().getEmail())) {
      return byUsername.get().getEmail();
    }

    throw new IllegalArgumentException("identifier must be a valid email or an existing username");
  }
}
