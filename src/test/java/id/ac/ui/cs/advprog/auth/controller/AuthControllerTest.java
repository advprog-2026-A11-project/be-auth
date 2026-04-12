package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.dto.auth.ChangePasswordRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.LoginRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.LogoutResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.RefreshTokenRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.RegisterRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.security.AuthenticatedUserPrincipal;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.AuthLoginService;
import id.ac.ui.cs.advprog.auth.service.AuthSessionService;
import id.ac.ui.cs.advprog.auth.service.GoogleSsoService;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

class AuthControllerTest {

  @Mock
  private SupabaseJwtService jwtService;

  @Mock
  private AuthLoginService authLoginService;

  @Mock
  private GoogleSsoService googleSsoService;

  @Mock
  private UserProfileService profileService;

  @Mock
  private AuthSessionService authSessionService;

  @Mock
  private CurrentUserProvider currentUserProvider;

  private AuthController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    controller = new AuthController(
        authLoginService,
        authSessionService,
        googleSsoService,
        jwtService,
        profileService,
        currentUserProvider,
        true);
  }

  @Test
  void meMissingHeaderReturnsUnauthorized() {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);
    ResponseEntity<Map<String, Object>> resp = controller.me(req);
    assertEquals(401, resp.getStatusCodeValue());
    assertTrue(resp.getBody().containsKey("error"));
  }

  @Test
  void meNonBearerHeaderReturnsUnauthorized() {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Basic abc");

    ResponseEntity<Map<String, Object>> resp = controller.me(req);

    assertEquals(401, resp.getStatusCodeValue());
    assertEquals("Missing Bearer token", resp.getBody().get("error"));
  }

  @Test
  void meInvalidTokenReturnsUnauthorized() {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Bearer bad");
    when(jwtService.validateAccessToken("bad"))
        .thenThrow(new SupabaseJwtService.InvalidTokenException("bad token"));
    ResponseEntity<Map<String, Object>> resp = controller.me(req);
    assertEquals(401, resp.getStatusCodeValue());
  }

  @Test
  void meReturnsProfileWhenPresent() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Bearer tkn");

    Jwt jwt = mock(Jwt.class);
    when(jwt.getClaimAsString("email")).thenReturn("a@b");
    when(jwt.getSubject()).thenReturn("sub");
    when(jwt.getClaimAsString("role")).thenReturn("USER");
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("http://iss"));
    when(jwt.getExpiresAt()).thenReturn(java.time.Instant.now());
    when(jwt.getExpiresAt()).thenReturn(Instant.now());

    when(jwtService.validateAccessToken("tkn")).thenReturn(jwt);

    UserProfile user = new UserProfile();
    user.setId(UUID.randomUUID());
    user.setUsername("u");
    user.setEmail("a@b");
    user.setDisplayName("dn");
    user.setRole("USER");
    user.setPhone("+628123456789");
    user.setAuthProvider("PASSWORD");
    user.setGoogleSub("google-sub-1");
    user.setActive(true);

    when(profileService.findByEmail("a@b")).thenReturn(Optional.of(user));

    ResponseEntity<Map<String, Object>> resp = controller.me(req);
    assertEquals(200, resp.getStatusCodeValue());
    assertNotNull(resp.getBody().get("profile"));
    @SuppressWarnings("unchecked")
    Map<String, Object> profilePayload = (Map<String, Object>) resp.getBody().get("profile");
    assertEquals("+628123456789", profilePayload.get("phone"));
    assertEquals("PASSWORD", profilePayload.get("authProvider"));
    assertEquals("google-sub-1", profilePayload.get("googleSub"));
  }

  @Test
  void meUsesSupabaseUserIdProfileWithoutEmailFallback() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Bearer tkn-sub");

    Jwt jwt = mock(Jwt.class);
    when(jwt.getClaimAsString("email")).thenReturn("sub@example.com");
    when(jwt.getSubject()).thenReturn("sub-123");
    when(jwt.getClaimAsString("role")).thenReturn("USER");
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("http://iss"));
    when(jwt.getExpiresAt()).thenReturn(Instant.now());
    when(jwtService.validateAccessToken("tkn-sub")).thenReturn(jwt);

    UserProfile user = new UserProfile();
    user.setSupabaseUserId("sub-123");
    user.setEmail("sub@example.com");
    when(profileService.findBySupabaseUserId("sub-123")).thenReturn(Optional.of(user));

    ResponseEntity<Map<String, Object>> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    verify(profileService).findBySupabaseUserId("sub-123");
    verify(profileService, never()).findByEmail("sub@example.com");
  }

  @Test
  void meReturnsNullProfileWhenAbsent() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Bearer tkn2");

    Jwt jwt = mock(Jwt.class);
    when(jwt.getClaimAsString("email")).thenReturn("x@y");
    when(jwt.getSubject()).thenReturn("sub");
    when(jwt.getClaimAsString("role")).thenReturn("USER");
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("http://iss"));
    when(jwt.getExpiresAt()).thenReturn(java.time.Instant.now());
    when(jwt.getExpiresAt()).thenReturn(Instant.now());

    when(jwtService.validateAccessToken("tkn2")).thenReturn(jwt);
    when(profileService.findByEmail("x@y")).thenReturn(Optional.empty());

    ResponseEntity<Map<String, Object>> resp = controller.me(req);
    assertEquals(200, resp.getStatusCodeValue());
    assertNull(resp.getBody().get("profile"));
  }

  @Test
  void registerReturnsCreated() {
    RegisterRequest request = new RegisterRequest(
        "new@example.com",
        "password123",
        "newuser",
        "New User");
    LoginResponse response = new LoginResponse(
        "access",
        "refresh",
        "Bearer",
        3600L,
        "supabase-user-id",
        "USER",
        "Registration successful");
    when(authLoginService.register(
        "new@example.com",
        "password123",
        "newuser",
        "New User")).thenReturn(response);

    ResponseEntity<LoginResponse> result = controller.register(request);

    assertEquals(201, result.getStatusCodeValue());
    assertNotNull(result.getBody());
    assertEquals("supabase-user-id", result.getBody().userId());
  }

  @Test
  void googleSsoUrlWithRedirectToUsesRedirectVersion() {
    when(googleSsoService.createSsoUrl("http://localhost:3000/callback"))
        .thenReturn(new SsoUrlResponse("google", "https://sso", null));

    ResponseEntity<SsoUrlResponse> response =
        controller.googleSsoUrl("http://localhost:3000/callback");

    assertEquals(200, response.getStatusCodeValue());
    assertEquals("https://sso", response.getBody().authorizationUrl());
    verify(googleSsoService).createSsoUrl("http://localhost:3000/callback");
    verify(googleSsoService, never()).createSsoUrl();
  }

  @Test
  void loginThrowsForbiddenWhenPasswordAuthDisabled() {
    AuthController disabledController = new AuthController(
        authLoginService,
        authSessionService,
        googleSsoService,
        jwtService,
        profileService,
        currentUserProvider,
        false);

    LoginRequest request = new LoginRequest("user@example.com", "password123");
    ResponseStatusException ex =
        assertThrows(ResponseStatusException.class, () -> disabledController.login(request));
    assertEquals(403, ex.getStatusCode().value());
  }

  @Test
  void meFallsBackToEmailLookupWhenSubIsBlank() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Bearer tkn-email-only");

    Jwt jwt = mock(Jwt.class);
    when(jwt.getClaimAsString("email")).thenReturn("fallback@example.com");
    when(jwt.getSubject()).thenReturn(" ");
    when(jwt.getClaimAsString("role")).thenReturn("USER");
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("http://iss"));
    when(jwt.getExpiresAt()).thenReturn(Instant.now());
    when(jwtService.validateAccessToken("tkn-email-only")).thenReturn(jwt);

    UserProfile user = new UserProfile();
    user.setEmail("fallback@example.com");
    user.setUsername("fallback-user");
    when(profileService.findByEmail("fallback@example.com")).thenReturn(Optional.of(user));

    ResponseEntity<Map<String, Object>> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    verify(profileService, never()).findBySupabaseUserId(anyString());
    verify(profileService).findByEmail("fallback@example.com");
  }

  @Test
  void meSkipsProfileLookupWhenSubjectAndEmailAreBlank() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Bearer tkn-no-profile");

    Jwt jwt = mock(Jwt.class);
    when(jwt.getClaimAsString("email")).thenReturn(" ");
    when(jwt.getSubject()).thenReturn(" ");
    when(jwt.getClaimAsString("role")).thenReturn("USER");
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("http://iss"));
    when(jwt.getExpiresAt()).thenReturn(Instant.now());
    when(jwtService.validateAccessToken("tkn-no-profile")).thenReturn(jwt);

    ResponseEntity<Map<String, Object>> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    assertNull(resp.getBody().get("profile"));
    verify(profileService, never()).findBySupabaseUserId(anyString());
    verify(profileService, never()).findByEmail(anyString());
  }

  @Test
  void meReturnsNullProfileWhenProfileLookupThrowsDataAccessException() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Bearer tkn-err");

    Jwt jwt = mock(Jwt.class);
    when(jwt.getClaimAsString("email")).thenReturn("error@example.com");
    when(jwt.getSubject()).thenReturn("sub-error");
    when(jwt.getClaimAsString("role")).thenReturn("USER");
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("http://iss"));
    when(jwt.getExpiresAt()).thenReturn(Instant.now());
    when(jwtService.validateAccessToken("tkn-err")).thenReturn(jwt);
    when(profileService.findBySupabaseUserId("sub-error"))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    ResponseEntity<Map<String, Object>> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    assertNull(resp.getBody().get("profile"));
  }

  @Test
  void refreshReturnsOk() {
    RefreshTokenRequest request = new RefreshTokenRequest("refresh-token");
    LoginResponse response = new LoginResponse(
        "new-access",
        "new-refresh",
        "Bearer",
        3600L,
        "supabase-user-id",
        "USER",
        "Session refreshed");
    when(authSessionService.refresh("refresh-token")).thenReturn(response);

    ResponseEntity<LoginResponse> result = controller.refresh(request);

    assertEquals(200, result.getStatusCodeValue());
    assertNotNull(result.getBody());
    assertEquals("new-access", result.getBody().accessToken());
    assertEquals("new-refresh", result.getBody().refreshToken());
  }

  @Test
  void logoutReturnsOkWhenBearerTokenPresent() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Authorization")).thenReturn("Bearer access-token");

    ResponseEntity<LogoutResponse> result = controller.logout(request);

    assertEquals(200, result.getStatusCodeValue());
    assertNotNull(result.getBody());
    assertEquals("Logout successful", result.getBody().message());
    verify(authSessionService).logout("access-token");
  }

  @Test
  void logoutThrowsUnauthorizedWhenBearerTokenIsMissing() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Authorization")).thenReturn(null);

    ResponseStatusException ex =
        assertThrows(ResponseStatusException.class, () -> controller.logout(request));

    assertEquals(401, ex.getStatusCode().value());
    assertEquals("Missing Bearer token", ex.getReason());
  }

  @Test
  void logoutThrowsUnauthorizedWhenAuthorizationIsNotBearer() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Authorization")).thenReturn("Basic token");

    ResponseStatusException ex =
        assertThrows(ResponseStatusException.class, () -> controller.logout(request));

    assertEquals(401, ex.getStatusCode().value());
    assertEquals("Missing Bearer token", ex.getReason());
  }

  @Test
  void logoutThrowsUnauthorizedWhenBearerTokenIsEmpty() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Authorization")).thenReturn("Bearer   ");

    ResponseStatusException ex =
        assertThrows(ResponseStatusException.class, () -> controller.logout(request));

    assertEquals(401, ex.getStatusCode().value());
    assertEquals("Bearer token is empty", ex.getReason());
  }

  @Test
  void changePasswordThrowsUnauthorizedWhenCurrentUserIsMissing() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.empty());

    ResponseStatusException ex = assertThrows(
        ResponseStatusException.class,
        () -> controller.changePassword(
            new ChangePasswordRequest("current-password", "new-password"),
            request));

    assertEquals(401, ex.getStatusCode().value());
    assertEquals("No authenticated user in security context", ex.getReason());
  }

  @Test
  void changePasswordThrowsUnauthorizedWhenBearerTokenIsEmpty() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(currentUserProvider.getCurrentUser())
        .thenReturn(Optional.of(
            new AuthenticatedUserPrincipal("sub-123", "user@example.com", "USER")));
    when(request.getHeader("Authorization")).thenReturn("Bearer   ");

    ResponseStatusException ex = assertThrows(
        ResponseStatusException.class,
        () -> controller.changePassword(
            new ChangePasswordRequest("current-password", "new-password"),
            request));

    assertEquals(401, ex.getStatusCode().value());
    assertEquals("Bearer token is empty", ex.getReason());
  }
}
