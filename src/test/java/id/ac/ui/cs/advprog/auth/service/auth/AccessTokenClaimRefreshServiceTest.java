package id.ac.ui.cs.advprog.auth.service.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.jwt.Jwt;

class AccessTokenClaimRefreshServiceTest {

  @Mock
  private SupabaseJwtService supabaseJwtService;

  @Mock
  private SupabaseAuthClient supabaseAuthClient;

  private AccessTokenClaimRefreshService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new AccessTokenClaimRefreshService(supabaseJwtService, supabaseAuthClient);
  }

  @Test
  void ensurePublicUserIdClaimKeepsSessionWhenClaimAlreadyPresent() {
    SupabaseAuthClient.LoginResult session = new SupabaseAuthClient.LoginResult(
        "access-token",
        "refresh-token",
        3600L,
        "sub-123",
        "user@example.com",
        "authenticated");
    when(supabaseJwtService.validateAccessToken("access-token"))
        .thenReturn(jwt("access-token", "c1f84e7b-bb84-412d-81bb-4449df141f11"));

    SupabaseAuthClient.LoginResult resolved = service.ensurePublicUserIdClaim(session);

    assertEquals("access-token", resolved.accessToken());
    verify(supabaseAuthClient, never()).refreshSession("refresh-token");
  }

  @Test
  void ensurePublicUserIdClaimRefreshesSessionWhenClaimIsMissing() {
    SupabaseAuthClient.LoginResult session = new SupabaseAuthClient.LoginResult(
        "access-token",
        "refresh-token",
        3600L,
        "sub-123",
        "user@example.com",
        "authenticated");
    SupabaseAuthClient.LoginResult refreshed = new SupabaseAuthClient.LoginResult(
        "access-token-2",
        "refresh-token-2",
        3600L,
        "sub-123",
        "user@example.com",
        "authenticated");
    when(supabaseJwtService.validateAccessToken("access-token"))
        .thenReturn(jwt("access-token", null));
    when(supabaseAuthClient.refreshSession("refresh-token")).thenReturn(refreshed);

    SupabaseAuthClient.LoginResult resolved = service.ensurePublicUserIdClaim(session);

    assertEquals("access-token-2", resolved.accessToken());
    assertEquals("refresh-token-2", resolved.refreshToken());
  }

  @Test
  void ensurePublicUserIdClaimSkipsRefreshWithoutRefreshToken() {
    SupabaseAuthClient.LoginResult session = new SupabaseAuthClient.LoginResult(
        "access-token",
        "",
        3600L,
        "sub-123",
        "user@example.com",
        "authenticated");

    SupabaseAuthClient.LoginResult resolved = service.ensurePublicUserIdClaim(session);

    assertEquals("access-token", resolved.accessToken());
    verify(supabaseJwtService, never()).validateAccessToken("access-token");
  }

  @Test
  void ensurePublicUserIdClaimSkipsRefreshWithoutAccessToken() {
    SupabaseAuthClient.LoginResult session = new SupabaseAuthClient.LoginResult(
        "",
        "refresh-token",
        3600L,
        "sub-123",
        "user@example.com",
        "authenticated");

    SupabaseAuthClient.LoginResult resolved = service.ensurePublicUserIdClaim(session);

    assertEquals("", resolved.accessToken());
    verify(supabaseJwtService, never()).validateAccessToken("access-token");
  }

  @Test
  void ensurePublicUserIdClaimTokensKeepsTokensWhenClaimAlreadyPresent() {
    when(supabaseJwtService.validateAccessToken("access-token"))
        .thenReturn(jwt("access-token", "c1f84e7b-bb84-412d-81bb-4449df141f11"));

    AccessTokenClaimRefreshService.SessionTokens resolved =
        service.ensurePublicUserIdClaim("access-token", "refresh-token");

    assertEquals("access-token", resolved.accessToken());
    assertEquals("refresh-token", resolved.refreshToken());
    verify(supabaseAuthClient, never()).refreshSession("refresh-token");
  }

  @Test
  void ensurePublicUserIdClaimTokensRefreshesWhenClaimIsMissing() {
    when(supabaseJwtService.validateAccessToken("access-token"))
        .thenReturn(jwt("access-token", null));
    when(supabaseAuthClient.refreshSession("refresh-token"))
        .thenReturn(new SupabaseAuthClient.LoginResult(
            "access-token-2",
            "refresh-token-2",
            3600L,
            "sub-123",
            "user@example.com",
            "authenticated"));

    AccessTokenClaimRefreshService.SessionTokens resolved =
        service.ensurePublicUserIdClaim("access-token", "refresh-token");

    assertEquals("access-token-2", resolved.accessToken());
    assertEquals("refresh-token-2", resolved.refreshToken());
  }

  @Test
  void ensurePublicUserIdClaimTokensSkipsValidationWithoutAccessToken() {
    AccessTokenClaimRefreshService.SessionTokens resolved =
        service.ensurePublicUserIdClaim("", "refresh-token");

    assertEquals("", resolved.accessToken());
    assertEquals("refresh-token", resolved.refreshToken());
    verify(supabaseJwtService, never()).validateAccessToken("access-token");
  }

  @Test
  void ensurePublicUserIdClaimTokensSkipsValidationWithoutRefreshToken() {
    AccessTokenClaimRefreshService.SessionTokens resolved =
        service.ensurePublicUserIdClaim("access-token", "");

    assertEquals("access-token", resolved.accessToken());
    assertEquals("", resolved.refreshToken());
    verify(supabaseJwtService, never()).validateAccessToken("access-token");
  }

  private Jwt jwt(String tokenValue, String publicUserId) {
    Map<String, Object> claims = new java.util.LinkedHashMap<>();
    claims.put("sub", "sub-123");
    claims.put("email", "user@example.com");
    claims.put("role", "authenticated");
    claims.put("aud", List.of("authenticated"));
    claims.put("iss", "https://supabase.test/auth/v1");
    if (publicUserId != null) {
      claims.put("yomu_user_id", publicUserId);
    }

    Instant now = Instant.now();
    return new Jwt(tokenValue, now, now.plusSeconds(3600), Map.of("alg", "none"), claims);
  }
}
