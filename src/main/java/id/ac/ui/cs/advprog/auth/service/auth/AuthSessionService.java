package id.ac.ui.cs.advprog.auth.service.auth;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.LoginResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.Role;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import id.ac.ui.cs.advprog.auth.service.state.TokenRevocationService;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class AuthSessionService {

  private final SupabaseAuthClient supabaseAuthClient;
  private final SupabaseJwtService supabaseJwtService;
  private final TokenRevocationService tokenRevocationService;
  private final UserProfileService userProfileService;

  public AuthSessionService(
      SupabaseAuthClient supabaseAuthClient,
      SupabaseJwtService supabaseJwtService,
      TokenRevocationService tokenRevocationService,
      UserProfileService userProfileService) {
    this.supabaseAuthClient = supabaseAuthClient;
    this.supabaseJwtService = supabaseJwtService;
    this.tokenRevocationService = tokenRevocationService;
    this.userProfileService = userProfileService;
  }

  public LoginResponse refresh(String refreshToken) {
    SupabaseAuthClient.LoginResult result = supabaseAuthClient.refreshSession(refreshToken);

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
          Role.canonicalize(profile.getRole()),
          "Session refreshed");
    } catch (DataAccessException ex) {
      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          null,
          Role.canonicalize(result.role()),
          "Session refreshed. Profile sync pending (database unavailable)");
    }
  }

  public void logout(String accessToken) {
    Jwt jwt = supabaseJwtService.validateAccessToken(accessToken);
    tokenRevocationService.revoke(accessToken, jwt.getExpiresAt());
    supabaseAuthClient.logout(accessToken);
  }

  public void revokeCurrentAccessToken(String accessToken) {
    if (!org.springframework.util.StringUtils.hasText(accessToken)) {
      return;
    }

    Jwt jwt = supabaseJwtService.validateAccessToken(accessToken);
    tokenRevocationService.revoke(accessToken, jwt.getExpiresAt());
  }

  public UserProfile changeEmail(
      String accessToken,
      String publicUserId,
      String currentEmail,
      String newEmail) {
    UserProfile updated = userProfileService.updateCurrentUserEmail(
        publicUserId,
        newEmail);

    try {
      supabaseAuthClient.updateEmail(accessToken, newEmail);
      return updated;
    } catch (RuntimeException ex) {
      userProfileService.updateCurrentUserEmail(
          publicUserId,
          currentEmail);
      throw ex;
    }
  }

  public void changePassword(
      String accessToken,
      String publicUserId,
      String supabaseUserId,
      String email,
      String currentPassword,
      String newPassword) {
    UserProfile profile = userProfileService.findByPublicUserId(publicUserId)
        .orElseThrow(() -> new IllegalArgumentException("User profile not found"));
    if (supportsPasswordAuth(profile)) {
      if (!StringUtils.hasText(currentPassword)) {
        throw new IllegalArgumentException("currentPassword is required");
      }
      supabaseAuthClient.loginWithPassword(email, currentPassword);
    } else if (!supportsGoogleOnlyPasswordSetup(profile, supabaseUserId)) {
      throw new UnauthorizedException("This account cannot change password yet.");
    }

    supabaseAuthClient.updatePassword(accessToken, newPassword);

    if (!supportsPasswordAuth(profile)) {
      userProfileService.markCurrentUserPasswordEnabled(publicUserId);
    }
  }

  private boolean supportsPasswordAuth(UserProfile profile) {
    return containsProvider(profile.getAuthProvider(), "PASSWORD");
  }

  private boolean supportsGoogleOnlyPasswordSetup(UserProfile profile, String supabaseUserId) {
    return StringUtils.hasText(profile.getGoogleSub())
        || (StringUtils.hasText(profile.getSupabaseUserId())
            && profile.getSupabaseUserId().equals(supabaseUserId)
            && containsProvider(profile.getAuthProvider(), "GOOGLE"));
  }

  private boolean containsProvider(String authProvider, String provider) {
    if (!StringUtils.hasText(authProvider)) {
      return false;
    }
    return authProvider.trim().toUpperCase().contains(provider);
  }

}


