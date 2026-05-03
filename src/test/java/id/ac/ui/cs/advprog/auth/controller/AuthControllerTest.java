package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthRequests.ChangePasswordRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthRequests.LoginRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthRequests.RefreshTokenRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthRequests.RegisterRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.LoginResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.LogoutResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.dto.common.CommonResponses.ErrorResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.security.AuthenticatedUserPrincipal;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.auth.AuthLoginService;
import id.ac.ui.cs.advprog.auth.service.auth.AuthSessionService;
import id.ac.ui.cs.advprog.auth.service.auth.SupabaseGoogleSsoService;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

class AuthControllerTest {

  @Mock
  private SupabaseJwtService jwtService;

  @Mock
  private AuthLoginService authLoginService;

  @Mock
  private SupabaseGoogleSsoService googleSsoService;

  @Mock
  private UserProfileService profileService;

  @Mock
  private AuthSessionService authSessionService;

  private CurrentUserProvider currentUserProvider;

  private AuthController controller;

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    currentUserProvider = spy(new CurrentUserProvider());
    controller = new AuthController(
        authLoginService,
        authSessionService,
        googleSsoService,
        profileService,
        currentUserProvider,
        true);
  }

  @Test
  void meMissingHeaderReturnsUnauthorized() {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);
    ResponseEntity<?> resp = controller.me(req);
    assertEquals(401, resp.getStatusCodeValue());
    assertEquals("Missing Bearer token", ((ErrorResponse) resp.getBody()).error());
  }

  @Test
  void meNonBearerHeaderReturnsUnauthorized() {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Basic abc");

    ResponseEntity<?> resp = controller.me(req);

    assertEquals(401, resp.getStatusCodeValue());
    assertEquals("Missing Bearer token", ((ErrorResponse) resp.getBody()).error());
  }

  @Test
  void meInvalidTokenReturnsUnauthorized() {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn("Bearer bad");
    ResponseEntity<?> resp = controller.me(req);
    assertEquals(401, resp.getStatusCodeValue());
  }

  @Test
  void meUsesAuthenticatedJwtFromSecurityContextWhenHeaderMissing() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);

    Jwt jwt = new Jwt(
        "security-context-token",
        Instant.now(),
        Instant.now().plusSeconds(600),
        Map.of("alg", "none"),
        Map.of(
            "sub", "ctx-sub-1",
            "email", "ctx@example.com",
            "role", "authenticated",
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));

    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(
            jwt,
            null,
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));

    UserProfile user = new UserProfile();
    user.setSupabaseUserId("ctx-sub-1");
    user.setEmail("ctx@example.com");
    user.setRole("ADMIN");
    when(profileService.findBySupabaseUserId("ctx-sub-1")).thenReturn(Optional.of(user));

    ResponseEntity<?> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    assertAuthMeResponseType(resp);
    assertEquals("ctx-sub-1", invokeRecordAccessor(resp.getBody(), "sub"));
    verify(jwtService, never()).validateAccessToken(anyString());
  }

  @Test
  void meReturnsProfileWhenPresent() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);
    authenticateJwt("sub", "a@b", "authenticated");

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

    ResponseEntity<?> resp = controller.me(req);
    assertEquals(200, resp.getStatusCodeValue());
    assertAuthMeResponseType(resp);
    Object profilePayload = invokeRecordAccessor(resp.getBody(), "profile");
    assertNotNull(profilePayload);
    assertEquals("+628123456789", invokeRecordAccessor(profilePayload, "phone"));
    assertEquals("PASSWORD", invokeRecordAccessor(profilePayload, "authProvider"));
    assertEquals("google-sub-1", invokeRecordAccessor(profilePayload, "googleSub"));
  }

  @Test
  void meUsesSupabaseUserIdProfileWithoutEmailFallback() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);
    authenticateJwt("sub-123", "sub@example.com", "authenticated");

    UserProfile user = new UserProfile();
    user.setSupabaseUserId("sub-123");
    user.setEmail("sub@example.com");
    when(profileService.findBySupabaseUserId("sub-123")).thenReturn(Optional.of(user));

    ResponseEntity<?> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    assertAuthMeResponseType(resp);
    verify(profileService).findBySupabaseUserId("sub-123");
    verify(profileService, never()).findByEmail("sub@example.com");
  }

  @Test
  void mePrefersPublicUserIdClaimWhenPresent() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);
    UUID publicUserId = UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11");
    authenticateJwtWithPublicUserId(
        "sub-123",
        "sub@example.com",
        "authenticated",
        publicUserId.toString());

    UserProfile user = new UserProfile();
    user.setId(publicUserId);
    user.setSupabaseUserId("sub-123");
    user.setEmail("sub@example.com");
    when(profileService.findByPublicUserId(publicUserId.toString())).thenReturn(Optional.of(user));

    ResponseEntity<?> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    assertAuthMeResponseType(resp);
    verify(profileService).findByPublicUserId(publicUserId.toString());
    verify(profileService, never()).findBySupabaseUserId(anyString());
    verify(profileService, never()).findByEmail(anyString());
  }

  @Test
  void meReturnsNullProfileWhenAbsent() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);
    authenticateJwt("sub", "x@y", "authenticated");
    when(profileService.findByEmail("x@y")).thenReturn(Optional.empty());

    ResponseEntity<?> resp = controller.me(req);
    assertEquals(200, resp.getStatusCodeValue());
    assertAuthMeResponseType(resp);
    assertNull(invokeRecordAccessor(resp.getBody(), "profile"));
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
        "535251d5-a941-49b0-9a04-5b26dc55ec61",
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
    assertEquals("535251d5-a941-49b0-9a04-5b26dc55ec61", result.getBody().userId());
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
    when(req.getHeader("Authorization")).thenReturn(null);
    authenticateJwt(" ", "fallback@example.com", "authenticated");

    UserProfile user = new UserProfile();
    user.setEmail("fallback@example.com");
    user.setUsername("fallback-user");
    when(profileService.findByEmail("fallback@example.com")).thenReturn(Optional.of(user));

    ResponseEntity<?> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    assertAuthMeResponseType(resp);
    verify(profileService, never()).findBySupabaseUserId(anyString());
    verify(profileService).findByEmail("fallback@example.com");
  }

  @Test
  void meSkipsProfileLookupWhenSubjectAndEmailAreBlank() throws Exception {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);
    authenticateJwt(" ", " ", "authenticated");

    ResponseEntity<?> resp = controller.me(req);

    assertEquals(200, resp.getStatusCodeValue());
    assertAuthMeResponseType(resp);
    assertNull(invokeRecordAccessor(resp.getBody(), "profile"));
    verify(profileService, never()).findBySupabaseUserId(anyString());
    verify(profileService, never()).findByEmail(anyString());
  }

  @Test
  void mePropagatesDataAccessExceptionWhenProfileLookupFails() {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getHeader("Authorization")).thenReturn(null);
    authenticateJwt("sub-error", "error@example.com", "authenticated");
    when(profileService.findBySupabaseUserId("sub-error"))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    DataAccessResourceFailureException ex = assertThrows(
        DataAccessResourceFailureException.class,
        () -> controller.me(req));

    assertEquals("db down", ex.getMessage());
  }

  @Test
  void refreshReturnsOk() {
    RefreshTokenRequest request = new RefreshTokenRequest("refresh-token");
    LoginResponse response = new LoginResponse(
        "new-access",
        "new-refresh",
        "Bearer",
        3600L,
        "535251d5-a941-49b0-9a04-5b26dc55ec61",
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

  private void assertAuthMeResponseType(ResponseEntity<?> response) {
    assertNotNull(response.getBody());
    assertEquals("AuthMeResponse", response.getBody().getClass().getSimpleName());
  }

  private Object invokeRecordAccessor(Object target, String accessorName) throws Exception {
    Method method = target.getClass().getMethod(accessorName);
    return method.invoke(target);
  }

  private void authenticateJwt(String sub, String email, String role) {
    authenticateJwtWithPublicUserId(sub, email, role, null);
  }

  private void authenticateJwtWithPublicUserId(
      String sub,
      String email,
      String role,
      String publicUserId) {
    Map<String, Object> claims = new java.util.LinkedHashMap<>();
    claims.put("sub", sub);
    claims.put("email", email);
    claims.put("role", role);
    claims.put("aud", List.of("authenticated"));
    claims.put("iss", "https://supabase.test/auth/v1");
    if (publicUserId != null) {
      claims.put("yomu_user_id", publicUserId);
    }

    Jwt jwt = new Jwt(
        "security-context-token",
        Instant.now(),
        Instant.now().plusSeconds(600),
        Map.of("alg", "none"),
        claims);

    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(
            jwt,
            null,
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
  }
}

