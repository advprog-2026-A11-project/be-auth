package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
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
    ensureAccountActive(email);
    SupabaseAuthClient.LoginResult result = supabaseAuthClient.loginWithPassword(email, password);

    try {
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
    } catch (DataAccessException ex) {
      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          result.supabaseUserId(),
          normalizeRole(result.role()),
          "Login successful. Profile sync pending (database unavailable)");
    }
  }

  public LoginResponse register(
      String email,
      String password,
      String username,
      String displayName) {
    SupabaseAuthClient.LoginResult result = supabaseAuthClient.registerWithPassword(
        email.trim().toLowerCase(),
        password,
        username,
        displayName);

    try {
      UserProfile profile = userProfileService.upsertFromIdentity(
          result.supabaseUserId(),
          result.email(),
          result.role());

      if (StringUtils.hasText(username) || StringUtils.hasText(displayName)) {
        profile = userProfileService.updateCurrentUserProfile(
            result.supabaseUserId(),
            result.email(),
            username,
            displayName);
      }

      String message = StringUtils.hasText(result.accessToken())
          ? "Registration successful"
          : "Registration successful. Please verify your email before login";

      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          profile.getSupabaseUserId(),
          profile.getRole(),
          message);
    } catch (DataAccessException ex) {
      String fallbackMessage = StringUtils.hasText(result.accessToken())
          ? "Registration successful. Profile sync pending (database unavailable)"
          : "Registration successful. Please verify email. "
              + "Profile sync pending (database unavailable)";
      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          result.supabaseUserId(),
          normalizeRole(result.role()),
          fallbackMessage);
    }
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
      if (!byUsername.get().isActive()) {
        throw new UnauthorizedException("Account is inactive");
      }
      return byUsername.get().getEmail();
    }

    throw new IllegalArgumentException("identifier must be a valid email or an existing username");
  }

  private void ensureAccountActive(String email) {
    userProfileService.findByEmail(email)
        .filter(existing -> !existing.isActive())
        .ifPresent(existing -> {
          throw new UnauthorizedException("Account is inactive");
        });
  }

  private String normalizeRole(String incomingRole) {
    if (!StringUtils.hasText(incomingRole)) {
      return "USER";
    }

    String normalized = incomingRole.trim().toUpperCase();
    if ("AUTHENTICATED".equals(normalized)) {
      return "USER";
    }
    if ("ADMIN".equals(normalized)) {
      return "ADMIN";
    }
    return "USER";
  }
}
