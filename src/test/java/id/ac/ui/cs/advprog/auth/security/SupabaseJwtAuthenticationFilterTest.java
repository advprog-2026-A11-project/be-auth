package id.ac.ui.cs.advprog.auth.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.TokenRevocationService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.FilterChain;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

class SupabaseJwtAuthenticationFilterTest {

  @Mock
  private SupabaseJwtService supabaseJwtService;

  @Mock
  private UserProfileService userProfileService;

  @Mock
  private TokenRevocationService tokenRevocationService;

  private SupabaseJwtAuthenticationFilter filter;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    filter = new SupabaseJwtAuthenticationFilter(
        supabaseJwtService,
        tokenRevocationService,
        userProfileService,
        new ObjectMapper());
    SecurityContextHolder.clearContext();
  }

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void shouldNotFilterHandlesAuthEndpointsAndNonApiPath() {
    final MockHttpServletRequest nonApi = new MockHttpServletRequest("GET", "/");
    final MockHttpServletRequest login = new MockHttpServletRequest("POST", "/api/auth/login");
    final MockHttpServletRequest register = new MockHttpServletRequest(
        "POST",
        "/api/auth/register");
    final MockHttpServletRequest refresh = new MockHttpServletRequest("POST", "/api/auth/refresh");
    final MockHttpServletRequest ssoUrl =
        new MockHttpServletRequest("GET", "/api/auth/sso/google/url");
    final MockHttpServletRequest ssoCallback = new MockHttpServletRequest(
        "POST",
        "/api/auth/sso/google/callback");
    final MockHttpServletRequest protectedApi = new MockHttpServletRequest("GET", "/api/users/me");

    assertTrue(filter.shouldNotFilter(nonApi));
    assertTrue(filter.shouldNotFilter(login));
    assertTrue(filter.shouldNotFilter(register));
    assertTrue(filter.shouldNotFilter(refresh));
    assertTrue(filter.shouldNotFilter(ssoUrl));
    assertTrue(filter.shouldNotFilter(ssoCallback));
    assertEquals(false, filter.shouldNotFilter(protectedApi));
  }

  @Test
  void shouldNotFilterRejectsUnexpectedMethodsForPublicAuthEndpoints() {
    final MockHttpServletRequest login = new MockHttpServletRequest("GET", "/api/auth/login");
    final MockHttpServletRequest register = new MockHttpServletRequest("GET", "/api/auth/register");
    final MockHttpServletRequest refresh = new MockHttpServletRequest("GET", "/api/auth/refresh");
    final MockHttpServletRequest ssoUrl =
        new MockHttpServletRequest("POST", "/api/auth/sso/google/url");
    final MockHttpServletRequest ssoCallback =
        new MockHttpServletRequest("GET", "/api/auth/sso/google/callback");

    assertFalse(filter.shouldNotFilter(login));
    assertFalse(filter.shouldNotFilter(register));
    assertFalse(filter.shouldNotFilter(refresh));
    assertFalse(filter.shouldNotFilter(ssoUrl));
    assertFalse(filter.shouldNotFilter(ssoCallback));
  }

  @Test
  void doFilterInternalPassesThroughWhenHeaderMissing() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  void doFilterInternalRejectsNonBearerHeader() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Basic abc");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    assertEquals(401, response.getStatus());
    assertTrue(
        response.getContentAsString().contains("Authorization header must use Bearer token"));
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void doFilterInternalRejectsEmptyBearerToken() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer   ");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    assertEquals(401, response.getStatus());
    assertTrue(response.getContentAsString().contains("Bearer token is empty"));
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void doFilterInternalRejectsInvalidToken() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer bad-token");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(supabaseJwtService.validateAccessToken("bad-token"))
        .thenThrow(new SupabaseJwtService.InvalidTokenException("bad token"));

    filter.doFilterInternal(request, response, chain);

    assertEquals(401, response.getStatus());
    assertTrue(response.getContentAsString().contains("bad token"));
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void doFilterInternalRejectsRevokedToken() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer revoked-token");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);
    when(tokenRevocationService.isRevoked("revoked-token")).thenReturn(true);

    filter.doFilterInternal(request, response, chain);

    assertEquals(401, response.getStatus());
    assertTrue(response.getContentAsString().contains("Session has been revoked"));
    verify(chain, never()).doFilter(request, response);
    verify(supabaseJwtService, never()).validateAccessToken(anyString());
  }

  @Test
  void doFilterInternalRejectsInactiveAccount() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-inactive");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    final Jwt jwt = jwt("valid-inactive", "sub-inactive", "inactive@example.com", "USER");
    UserProfile inactive = new UserProfile();
    inactive.setSupabaseUserId("sub-inactive");
    inactive.setEmail("inactive@example.com");
    inactive.setRole("USER");
    inactive.setActive(false);

    when(supabaseJwtService.validateAccessToken("valid-inactive")).thenReturn(jwt);
    when(userProfileService.findBySupabaseUserId("sub-inactive")).thenReturn(Optional.of(inactive));

    filter.doFilterInternal(request, response, chain);

    assertEquals(401, response.getStatus());
    assertTrue(response.getContentAsString().contains("Account is inactive"));
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void doFilterInternalAuthenticatesUsingTokenRoleWhenProfileAbsent() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-user");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    final Jwt jwt = jwt("valid-user", "sub-user", "user@example.com", "authenticated");
    when(supabaseJwtService.validateAccessToken("valid-user")).thenReturn(jwt);
    when(userProfileService.findBySupabaseUserId("sub-user")).thenReturn(Optional.empty());
    when(userProfileService.findByEmail("user@example.com")).thenReturn(Optional.empty());

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(auth.getAuthorities().stream().anyMatch(a -> "ROLE_USER".equals(a.getAuthority())));
    verify(chain).doFilter(request, response);
  }

  @Test
  void doFilterInternalUsesProfileRoleOverTokenRole() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest(
        "GET",
        "/api/admin/dashboard");
    request.addHeader("Authorization", "Bearer valid-admin");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    final Jwt jwt = jwt("valid-admin", "sub-admin", "admin@example.com", "USER");
    UserProfile admin = new UserProfile();
    admin.setSupabaseUserId("sub-admin");
    admin.setEmail("admin@example.com");
    admin.setRole("ADMIN");
    admin.setActive(true);

    when(supabaseJwtService.validateAccessToken("valid-admin")).thenReturn(jwt);
    when(userProfileService.findBySupabaseUserId("sub-admin")).thenReturn(Optional.of(admin));

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())));
    verify(chain).doFilter(request, response);
  }

  @Test
  void doFilterInternalFallsBackToEmailLookupWhenSubMissing() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-email");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    final Jwt jwt = jwt("valid-email", " ", "fallback@example.com", "USER");
    UserProfile user = new UserProfile();
    user.setSupabaseUserId("sub-fallback");
    user.setEmail("fallback@example.com");
    user.setRole("USER");
    user.setActive(true);

    when(supabaseJwtService.validateAccessToken("valid-email")).thenReturn(jwt);
    when(userProfileService.findByEmail("fallback@example.com")).thenReturn(Optional.of(user));

    filter.doFilterInternal(request, response, chain);

    verify(userProfileService, never()).findBySupabaseUserId(anyString());
    verify(userProfileService).findByEmail("fallback@example.com");
    verify(chain).doFilter(request, response);
  }

  @Test
  void doFilterInternalAuthenticatesWithoutAuthoritiesWhenRoleAndIdentityAreBlank()
      throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-blank-role");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    final Jwt jwt = jwt("valid-blank-role", " ", " ", " ");
    when(supabaseJwtService.validateAccessToken("valid-blank-role")).thenReturn(jwt);

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(auth != null);
    assertTrue(auth.getAuthorities().isEmpty());
    verify(userProfileService, never()).findBySupabaseUserId(anyString());
    verify(userProfileService, never()).findByEmail(anyString());
    verify(chain).doFilter(request, response);
  }

  @Test
  void doFilterInternalFallsBackToTokenRoleWhenProfileRoleBlank() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-blank-profile-role");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    final Jwt jwt = jwt(
        "valid-blank-profile-role",
        "sub-role-fallback",
        "role@example.com",
        "authenticated");
    UserProfile user = new UserProfile();
    user.setSupabaseUserId("sub-role-fallback");
    user.setEmail("role@example.com");
    user.setRole(" ");
    user.setActive(true);

    when(supabaseJwtService.validateAccessToken("valid-blank-profile-role")).thenReturn(jwt);
    when(userProfileService.findBySupabaseUserId("sub-role-fallback"))
        .thenReturn(Optional.of(user));

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(auth != null);
    assertTrue(auth.getAuthorities().stream().anyMatch(a -> "ROLE_USER".equals(a.getAuthority())));
    verify(chain).doFilter(request, response);
  }

  private Jwt jwt(String tokenValue, String sub, String email, String role) {
    Instant now = Instant.now();
    return new Jwt(
        tokenValue,
        now,
        now.plusSeconds(3600),
        Map.of("alg", "none"),
        Map.of(
            "sub", sub,
            "email", email,
            "role", role,
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));
  }
}
