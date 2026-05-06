package id.ac.ui.cs.advprog.auth.service.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.jwt.Jwt;

class AuthLoginServiceTest {

  @Mock
  private SupabaseAuthClient supabaseAuthClient;

  @Mock
  private UserProfileService userProfileService;

  @Mock
  private SupabaseJwtService supabaseJwtService;

  private AuthLoginService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new AuthLoginService(
        supabaseAuthClient,
        userProfileService,
        supabaseJwtService);
  }

  @Test
  void loginRejectsInactiveAccountByEmailBeforeCallingIdentityProvider() {
    UserProfile inactive = new UserProfile();
    inactive.setEmail("inactive@example.com");
    inactive.setActive(false);
    when(userProfileService.findByEmail("inactive@example.com")).thenReturn(Optional.of(inactive));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.login("inactive@example.com", "password123"));

    assertEquals(
        "Your account has been deactivated. Please contact an administrator.",
        ex.getMessage());
    verify(supabaseAuthClient, never()).loginWithPassword("inactive@example.com", "password123");
  }

  @Test
  void loginRejectsInactiveAccountByUsernameBeforeCallingIdentityProvider() {
    UserProfile inactive = new UserProfile();
    inactive.setUsername("inactive-user");
    inactive.setEmail("inactive@example.com");
    inactive.setActive(false);
    when(userProfileService.findByUsername("inactive-user")).thenReturn(Optional.of(inactive));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.login("inactive-user", "password123"));

    assertEquals(
        "Your account has been deactivated. Please contact an administrator.",
        ex.getMessage());
    verify(supabaseAuthClient, never()).loginWithPassword("inactive@example.com", "password123");
  }

  @Test
  void loginResolvesPhoneIdentifierToEmailBeforeCallingIdentityProvider() {
    UserProfile user = new UserProfile();
    user.setId(UUID.randomUUID());
    user.setPhone("+628123456789");
    user.setEmail("phone@example.com");
    user.setRole("STUDENT");
    user.setActive(true);
    when(userProfileService.findByUsername("+628123456789")).thenReturn(Optional.empty());
    when(userProfileService.findByPhone("+628123456789")).thenReturn(Optional.of(user));
    when(userProfileService.findByEmail("phone@example.com")).thenReturn(Optional.of(user));
    when(supabaseAuthClient.loginWithPassword("phone@example.com", "password123"))
        .thenReturn(new SupabaseAuthClient.LoginResult(
            "access-token",
            "refresh-token",
            3600L,
            "supabase-user-phone",
            "phone@example.com",
            "STUDENT"));
    when(userProfileService.upsertFromIdentity(
        "supabase-user-phone",
        "phone@example.com",
        "STUDENT")).thenReturn(user);
    when(supabaseJwtService.validateAccessToken("access-token"))
        .thenReturn(jwt("access-token", "c1f84e7b-bb84-412d-81bb-4449df141f11"));

    service.login("+628123456789", "password123");

    verify(supabaseAuthClient).loginWithPassword("phone@example.com", "password123");
  }

  @Test
  void loginNormalizesLocalPhoneIdentifierBeforeLookup() {
    UserProfile user = new UserProfile();
    user.setId(UUID.randomUUID());
    user.setPhone("+628123456789");
    user.setEmail("normalized-phone@example.com");
    user.setRole("STUDENT");
    user.setActive(true);

    when(userProfileService.findByPhone("+628123456789")).thenReturn(Optional.of(user));
    when(userProfileService.findByEmail("normalized-phone@example.com")).thenReturn(Optional.of(user));
    when(supabaseAuthClient.loginWithPassword("normalized-phone@example.com", "password123"))
        .thenReturn(new SupabaseAuthClient.LoginResult(
            "access-token",
            "refresh-token",
            3600L,
            "supabase-user-phone",
            "normalized-phone@example.com",
            "STUDENT"));
    when(userProfileService.upsertFromIdentity(
        "supabase-user-phone",
        "normalized-phone@example.com",
        "STUDENT")).thenReturn(user);
    when(supabaseJwtService.validateAccessToken("access-token"))
        .thenReturn(jwt("access-token", "c1f84e7b-bb84-412d-81bb-4449df141f11"));

    service.login("0812-345-6789", "password123");

    verify(userProfileService).findByPhone("+628123456789");
    verify(supabaseAuthClient).loginWithPassword("normalized-phone@example.com", "password123");
  }

  @Test
  void loginFailsClosedWhenPhoneIdentifierResolvesToProfileWithoutEmail() {
    UserProfile user = new UserProfile();
    user.setPhone("+628123456789");
    user.setUsername("phone-user");
    user.setEmail(" ");
    user.setActive(true);
    when(userProfileService.findByPhone("+628123456789")).thenReturn(Optional.of(user));

    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> service.login("08123456789", "password123"));

    assertEquals("phone login is not available for this account", ex.getMessage());
    verify(supabaseAuthClient, never()).loginWithPassword("phone-user", "password123");
  }

  @Test
  void loginRefreshesSessionWhenAccessTokenMissingPublicUserIdClaim() {
    UserProfile user = new UserProfile();
    user.setId(UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11"));
    user.setEmail("user@example.com");
    user.setRole("STUDENT");
    user.setActive(true);

    SupabaseAuthClient.LoginResult loginResult = new SupabaseAuthClient.LoginResult(
        "access-token",
        "refresh-token",
        3600L,
        "supabase-user-1",
        "user@example.com",
        "authenticated");
    SupabaseAuthClient.LoginResult refreshedResult = new SupabaseAuthClient.LoginResult(
        "access-token-2",
        "refresh-token-2",
        3600L,
        "supabase-user-1",
        "user@example.com",
        "authenticated");

    when(userProfileService.findByEmail("user@example.com")).thenReturn(Optional.of(user));
    when(supabaseAuthClient.loginWithPassword("user@example.com", "password123"))
        .thenReturn(loginResult);
    when(userProfileService.upsertFromIdentity(
        "supabase-user-1",
        "user@example.com",
        "authenticated"))
        .thenReturn(user);
    when(supabaseJwtService.validateAccessToken("access-token"))
        .thenReturn(jwt("access-token", null));
    when(supabaseAuthClient.refreshSession("refresh-token")).thenReturn(refreshedResult);

    var response = service.login("user@example.com", "password123");

    assertEquals("access-token-2", response.accessToken());
    assertEquals("refresh-token-2", response.refreshToken());
  }

  @Test
  void loginRejectsInactiveAccountByPhoneBeforeCallingIdentityProvider() {
    UserProfile inactive = new UserProfile();
    inactive.setPhone("+628999999999");
    inactive.setEmail("inactive-phone@example.com");
    inactive.setActive(false);
    when(userProfileService.findByUsername("+628999999999")).thenReturn(Optional.empty());
    when(userProfileService.findByPhone("+628999999999")).thenReturn(Optional.of(inactive));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.login("+628999999999", "password123"));

    assertEquals(
        "Your account has been deactivated. Please contact an administrator.",
        ex.getMessage());
    verify(supabaseAuthClient, never())
        .loginWithPassword("inactive-phone@example.com", "password123");
  }

  private Jwt jwt(String tokenValue, String publicUserId) {
    Map<String, Object> claims = new java.util.LinkedHashMap<>();
    claims.put("sub", "supabase-user-1");
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


