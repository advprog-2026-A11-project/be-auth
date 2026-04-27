package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.oauth2.jwt.Jwt;

class AuthSessionServiceTest {

  @Mock
  private SupabaseAuthClient supabaseAuthClient;

  @Mock
  private SupabaseJwtService supabaseJwtService;

  @Mock
  private TokenRevocationService tokenRevocationService;

  @Mock
  private UserProfileService userProfileService;

  private AuthSessionService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new AuthSessionService(
        supabaseAuthClient,
        supabaseJwtService,
        tokenRevocationService,
        userProfileService);
  }

  @Test
  void changePasswordUpdatesWhenCurrentPasswordIsValid() {
    when(supabaseAuthClient.loginWithPassword("user@example.com", "current-password"))
        .thenReturn(new SupabaseAuthClient.LoginResult(
            "access-token",
            "refresh-token",
            3600L,
            "sub-123",
            "user@example.com",
            "USER"));

    service.changePassword(
        "access-token",
        "user@example.com",
        "current-password",
        "new-password");

    verify(supabaseAuthClient).updatePassword("access-token", "new-password");
  }

  @Test
  void changePasswordRejectsWhenCurrentPasswordIsWrong() {
    when(supabaseAuthClient.loginWithPassword("user@example.com", "wrong-password"))
        .thenThrow(new UnauthorizedException("Invalid login credentials"));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.changePassword(
            "access-token",
            "user@example.com",
            "wrong-password",
            "new-password"));

    assertEquals("Invalid login credentials", ex.getMessage());
    verify(supabaseAuthClient, never()).updatePassword("access-token", "new-password");
  }

  @Test
  void changeEmailDelegatesToIdentityProvider() {
    service.changeEmail("access-token", "new@example.com");

    verify(supabaseAuthClient).updateEmail("access-token", "new@example.com");
  }

  @Test
  void changeEmailOrchestrationUpdatesLocalProfileThenIdentityProvider() throws Exception {
    UserProfile updated = new UserProfile();
    updated.setId(UUID.randomUUID());
    updated.setSupabaseUserId("sub-123");
    updated.setEmail("new@example.com");

    when(userProfileService.updateCurrentUserEmail("sub-123", "old@example.com", "new@example.com"))
        .thenReturn(updated);

    invokeCoordinatedChangeEmail(
        "access-token",
        "sub-123",
        "old@example.com",
        "new@example.com");

    verify(userProfileService).updateCurrentUserEmail("sub-123", "old@example.com", "new@example.com");
    verify(supabaseAuthClient).updateEmail("access-token", "new@example.com");
    verify(userProfileService, never()).updateCurrentUserEmail(
        "sub-123",
        "new@example.com",
        "old@example.com");
  }

  @Test
  void changeEmailOrchestrationRollsBackLocalProfileWhenIdentityProviderFails()
      throws Exception {
    UserProfile updated = new UserProfile();
    updated.setId(UUID.randomUUID());
    updated.setSupabaseUserId("sub-123");
    updated.setEmail("new@example.com");

    when(userProfileService.updateCurrentUserEmail("sub-123", "old@example.com", "new@example.com"))
        .thenReturn(updated);
    doThrow(new IllegalStateException("Identity provider unavailable"))
        .when(supabaseAuthClient)
        .updateEmail("access-token", "new@example.com");

    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> invokeCoordinatedChangeEmail(
            "access-token",
            "sub-123",
            "old@example.com",
            "new@example.com"));

    assertEquals("Identity provider unavailable", ex.getMessage());
    verify(userProfileService).updateCurrentUserEmail("sub-123", "old@example.com", "new@example.com");
    verify(userProfileService).updateCurrentUserEmail("sub-123", "new@example.com", "old@example.com");
  }

  @Test
  void refreshReturnsSyncedProfileWhenDatabaseIsAvailable() {
    final SupabaseAuthClient.LoginResult result = new SupabaseAuthClient.LoginResult(
        "new-access",
        "new-refresh",
        3600L,
        "sub-123",
        "user@example.com",
        "USER");
    UserProfile profile = new UserProfile();
    profile.setId(UUID.randomUUID());
    profile.setSupabaseUserId("sub-123");
    profile.setRole("ADMIN");
    when(supabaseAuthClient.refreshSession("refresh-token")).thenReturn(result);
    when(userProfileService.upsertFromIdentity("sub-123", "user@example.com", "USER"))
        .thenReturn(profile);

    var response = service.refresh("refresh-token");

    assertEquals(profile.getId().toString(), response.userId());
    assertEquals("ADMIN", response.role());
    assertEquals("Session refreshed", response.message());
  }

  @Test
  void refreshFallsBackToDefaultUserRoleWhenProfileSyncFailsWithoutRole() {
    SupabaseAuthClient.LoginResult result = new SupabaseAuthClient.LoginResult(
        "new-access",
        "new-refresh",
        3600L,
        "sub-123",
        "user@example.com",
        null);
    when(supabaseAuthClient.refreshSession("refresh-token")).thenReturn(result);
    when(userProfileService.upsertFromIdentity("sub-123", "user@example.com", null))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    var response = service.refresh("refresh-token");

    assertEquals("STUDENT", response.role());
    assertTrue(response.message().contains("Profile sync pending"));
  }

  @Test
  void refreshFallsBackToUserRoleWhenSupabaseRoleIsAuthenticated() {
    SupabaseAuthClient.LoginResult result = new SupabaseAuthClient.LoginResult(
        "new-access",
        "new-refresh",
        3600L,
        "sub-123",
        "user@example.com",
        "authenticated");
    when(supabaseAuthClient.refreshSession("refresh-token")).thenReturn(result);
    when(userProfileService.upsertFromIdentity("sub-123", "user@example.com", "authenticated"))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    var response = service.refresh("refresh-token");

    assertEquals("STUDENT", response.role());
  }

  @Test
  void refreshFallsBackToAdminRoleWhenSupabaseRoleIsAdmin() {
    SupabaseAuthClient.LoginResult result = new SupabaseAuthClient.LoginResult(
        "new-access",
        "new-refresh",
        3600L,
        "sub-123",
        "user@example.com",
        "admin");
    when(supabaseAuthClient.refreshSession("refresh-token")).thenReturn(result);
    when(userProfileService.upsertFromIdentity("sub-123", "user@example.com", "admin"))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    var response = service.refresh("refresh-token");

    assertEquals("ADMIN", response.role());
  }

  @Test
  void refreshFallsBackToUserRoleWhenSupabaseRoleIsUnknown() {
    SupabaseAuthClient.LoginResult result = new SupabaseAuthClient.LoginResult(
        "new-access",
        "new-refresh",
        3600L,
        "sub-123",
        "user@example.com",
        "moderator");
    when(supabaseAuthClient.refreshSession("refresh-token")).thenReturn(result);
    when(userProfileService.upsertFromIdentity("sub-123", "user@example.com", "moderator"))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    var response = service.refresh("refresh-token");

    assertEquals("STUDENT", response.role());
  }

  @Test
  void revokeCurrentAccessTokenReturnsEarlyWhenTokenIsBlank() {
    service.revokeCurrentAccessToken(" ");

    verify(supabaseJwtService, never()).validateAccessToken(any());
    verify(tokenRevocationService, never()).revoke(any(), any());
  }

  @Test
  void revokeCurrentAccessTokenRevokesWhenTokenIsPresent() {
    Jwt jwt = new Jwt(
        "access-token",
        Instant.now(),
        Instant.now().plusSeconds(300),
        Map.of("alg", "none"),
        Map.of("sub", "sub-123"));
    when(supabaseJwtService.validateAccessToken("access-token")).thenReturn(jwt);

    service.revokeCurrentAccessToken("access-token");

    verify(tokenRevocationService).revoke("access-token", jwt.getExpiresAt());
  }

  private void invokeCoordinatedChangeEmail(
      String accessToken,
      String supabaseUserId,
      String currentEmail,
      String newEmail) throws Exception {
    try {
      Method method = AuthSessionService.class.getMethod(
          "changeEmail",
          String.class,
          String.class,
          String.class,
          String.class);
      method.invoke(service, accessToken, supabaseUserId, currentEmail, newEmail);
    } catch (InvocationTargetException ex) {
      if (ex.getCause() instanceof Exception cause) {
        throw cause;
      }
      throw ex;
    }
  }
}
