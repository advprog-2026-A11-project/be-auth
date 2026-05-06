package id.ac.ui.cs.advprog.auth.service.auth;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.LoginResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.Role;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class AuthLoginService {

  private static final Pattern PHONE_IDENTIFIER_PATTERN = Pattern.compile("^\\+?[0-9]{8,15}$");
  private static final String DEACTIVATED_ACCOUNT_MESSAGE =
      "Your account has been deactivated. Please contact an administrator.";
  private static final String PHONE_NOT_REGISTERED_MESSAGE =
      "phone number is not registered";
  private static final String PHONE_LOGIN_UNAVAILABLE_MESSAGE =
      "phone login is not available for this account";

  private final SupabaseAuthClient supabaseAuthClient;
  private final UserProfileService userProfileService;
  private final SupabaseJwtService supabaseJwtService;

  public AuthLoginService(
      SupabaseAuthClient supabaseAuthClient,
      UserProfileService userProfileService,
      SupabaseJwtService supabaseJwtService) {
    this.supabaseAuthClient = supabaseAuthClient;
    this.userProfileService = userProfileService;
    this.supabaseJwtService = supabaseJwtService;
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
      result = ensurePublicUserIdClaim(result);

      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          profile.getId().toString(),
          Role.canonicalize(profile.getRole()),
          "Login successful");
    } catch (DataAccessException ex) {
      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          null,
          Role.canonicalize(result.role()),
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
        profile = userProfileService.updateIdentityProfile(
            result.supabaseUserId(),
            result.email(),
            username,
            displayName);
      }
      result = ensurePublicUserIdClaim(result);

      String message = StringUtils.hasText(result.accessToken())
          ? "Registration successful"
          : "Registration successful. Please verify your email before login";

      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          profile.getId().toString(),
          Role.canonicalize(profile.getRole()),
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
          Role.canonicalize(result.role()),
          fallbackMessage);
    }
  }

  private String resolveEmailIdentifier(String identifier) {
    if (!StringUtils.hasText(identifier)) {
      throw new IllegalArgumentException("identifier is required");
    }

    String normalizedIdentifier = identifier.trim();
    if (normalizedIdentifier.contains("@")) {
      return normalizedIdentifier;
    }

    String normalizedPhone = normalizePhoneIdentifier(normalizedIdentifier);
    if (normalizedPhone != null) {
      UserProfile profile = userProfileService.findByPhone(normalizedPhone)
          .orElseThrow(() -> new IllegalArgumentException(PHONE_NOT_REGISTERED_MESSAGE));
      return resolvePhoneLoginEmail(profile);
    }

    Optional<UserProfile> byUsername = userProfileService.findByUsername(normalizedIdentifier);
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
          throw new UnauthorizedException(DEACTIVATED_ACCOUNT_MESSAGE);
        });
  }

  private Optional<String> resolveEmailFromProfile(UserProfile profile) {
    if (!profile.isActive()) {
      throw new UnauthorizedException(DEACTIVATED_ACCOUNT_MESSAGE);
    }
    if (!StringUtils.hasText(profile.getEmail())) {
      return Optional.empty();
    }
    return Optional.of(profile.getEmail());
  }

  private String resolvePhoneLoginEmail(UserProfile profile) {
    return resolveEmailFromProfile(profile)
        .orElseThrow(() -> new IllegalArgumentException(PHONE_LOGIN_UNAVAILABLE_MESSAGE));
  }

  private String normalizePhoneIdentifier(String identifier) {
    String compact = identifier.replaceAll("[\\s\\-()]", "");
    if (!StringUtils.hasText(compact)) {
      return null;
    }

    if (compact.startsWith("08")) {
      compact = "+628" + compact.substring(2);
    } else if (compact.startsWith("628")) {
      compact = "+" + compact;
    }

    if (!PHONE_IDENTIFIER_PATTERN.matcher(compact).matches()) {
      return null;
    }

    return compact;
  }

  private SupabaseAuthClient.LoginResult ensurePublicUserIdClaim(
      SupabaseAuthClient.LoginResult session) {
    if (!StringUtils.hasText(session.accessToken())
        || !StringUtils.hasText(session.refreshToken())) {
      return session;
    }

    Jwt jwt = supabaseJwtService.validateAccessToken(session.accessToken());
    if (StringUtils.hasText(jwt.getClaimAsString("yomu_user_id"))) {
      return session;
    }

    return supabaseAuthClient.refreshSession(session.refreshToken());
  }

}

