package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
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
          profile.getSupabaseUserId(),
          profile.getRole(),
          "Session refreshed");
    } catch (DataAccessException ex) {
      return new LoginResponse(
          result.accessToken(),
          result.refreshToken(),
          "Bearer",
          result.expiresIn(),
          result.supabaseUserId(),
          normalizeRole(result.role()),
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

  private String normalizeRole(String incomingRole) {
    if (!org.springframework.util.StringUtils.hasText(incomingRole)) {
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
