package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.RegisterRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.AuthLoginService;
import id.ac.ui.cs.advprog.auth.service.GoogleSsoService;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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

  private AuthController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    controller = new AuthController(
        authLoginService,
        googleSsoService,
        jwtService,
        profileService,
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
    user.setId(10L);
    user.setUsername("u");
    user.setEmail("a@b");
    user.setDisplayName("dn");
    user.setRole("USER");
    user.setActive(true);

    when(profileService.findByEmail("a@b")).thenReturn(Optional.of(user));

    ResponseEntity<Map<String, Object>> resp = controller.me(req);
    assertEquals(200, resp.getStatusCodeValue());
    assertNotNull(resp.getBody().get("profile"));
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
        googleSsoService,
        jwtService,
        profileService,
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
}
