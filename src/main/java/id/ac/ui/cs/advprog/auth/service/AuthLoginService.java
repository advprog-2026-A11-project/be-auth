package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class AuthLoginService {

  private static final Pattern PHONE_IDENTIFIER_PATTERN = Pattern.compile("^\\+?[0-9]{8,15}$");
  private static final String BANNED_ACCOUNT_MESSAGE =
      "Your account has been banned. Please contact an administrator.";

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
          profile.getId().toString(),
          RoleMapper.canonicalize(profile.getRole()),
          "Login successful");
    } catch (DataAccessException ex) {
      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          null,
          RoleMapper.canonicalize(result.role()),
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
          profile.getId().toString(),
          RoleMapper.canonicalize(profile.getRole()),
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
          null,
          RoleMapper.canonicalize(result.role()),
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

    if (PHONE_IDENTIFIER_PATTERN.matcher(normalized).matches()) {
      Optional<String> resolvedPhone = userProfileService.findByPhone(normalized)
          .flatMap(this::resolveEmailFromProfile);
      if (resolvedPhone.isPresent()) {
        return resolvedPhone.get();
      }
    }

    Optional<UserProfile> byUsername = userProfileService.findByUsername(normalized);
    Optional<String> resolvedUsername = byUsername.flatMap(this::resolveEmailFromProfile);
    if (resolvedUsername.isPresent()) {
      return resolvedUsername.get();
    }

    throw new IllegalArgumentException(
        "identifier must be a valid email, phone, or an existing username");
  }

  private void ensureAccountActive(String email) {
    userProfileService.findByEmail(email)
        .filter(existing -> !existing.isActive())
        .ifPresent(existing -> {
          throw new UnauthorizedException(BANNED_ACCOUNT_MESSAGE);
        });
  }

  private Optional<String> resolveEmailFromProfile(UserProfile profile) {
    if (!profile.isActive()) {
      throw new UnauthorizedException(BANNED_ACCOUNT_MESSAGE);
    }
    if (!StringUtils.hasText(profile.getEmail())) {
      return Optional.empty();
    }
    return Optional.of(profile.getEmail());
  }

}
