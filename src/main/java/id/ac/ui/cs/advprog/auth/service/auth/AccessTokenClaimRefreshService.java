package id.ac.ui.cs.advprog.auth.service.auth;

import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class AccessTokenClaimRefreshService {

  private final SupabaseJwtService supabaseJwtService;
  private final SupabaseAuthClient supabaseAuthClient;

  public AccessTokenClaimRefreshService(
      SupabaseJwtService supabaseJwtService,
      SupabaseAuthClient supabaseAuthClient) {
    this.supabaseJwtService = supabaseJwtService;
    this.supabaseAuthClient = supabaseAuthClient;
  }

  public SupabaseAuthClient.LoginResult ensurePublicUserIdClaim(
      SupabaseAuthClient.LoginResult session) {
    if (!StringUtils.hasText(session.accessToken()) || !StringUtils.hasText(session.refreshToken())) {
      return session;
    }

    Jwt jwt = supabaseJwtService.validateAccessToken(session.accessToken());
    if (StringUtils.hasText(jwt.getClaimAsString("yomu_user_id"))) {
      return session;
    }

    return supabaseAuthClient.refreshSession(session.refreshToken());
  }
}
