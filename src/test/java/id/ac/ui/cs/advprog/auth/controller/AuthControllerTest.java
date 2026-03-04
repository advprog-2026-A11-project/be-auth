package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.RegisterRequest;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.AuthLoginService;
import id.ac.ui.cs.advprog.auth.service.GoogleSsoService;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;

class AuthControllerTest {

  @Mock
  private SupabaseJwtService jwtService;

  @Mock
  private AuthLoginService authLoginService;

  @Mock
  private GoogleSsoService googleSsoService;

  @Mock
  private UserProfileService profileService;

  @InjectMocks
  private AuthController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
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
}
