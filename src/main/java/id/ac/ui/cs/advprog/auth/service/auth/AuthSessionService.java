package id.ac.ui.cs.advprog.auth.service.auth;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.LoginResponse;
import id.ac.ui.cs.advprog.auth.model.Role;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import id.ac.ui.cs.advprog.auth.service.state.TokenRevocationService;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

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
      String email,
      String currentPassword,
      String newPassword) {
    supabaseAuthClient.loginWithPassword(email, currentPassword);
    supabaseAuthClient.updatePassword(accessToken, newPassword);
  }

}


