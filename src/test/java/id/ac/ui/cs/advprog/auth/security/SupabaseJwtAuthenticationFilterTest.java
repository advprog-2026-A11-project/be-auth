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
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.state.TokenRevocationService;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import jakarta.servlet.FilterChain;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
        tokenRevocationService,
        userProfileService,
        new CurrentUserProvider(),
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
    final MockHttpServletRequest protectedApi = new MockHttpServletRequest("GET", "/api/users/me");

    assertTrue(filter.shouldNotFilter(nonApi));
    assertTrue(filter.shouldNotFilter(login));
    assertTrue(filter.shouldNotFilter(register));
    assertTrue(filter.shouldNotFilter(refresh));
    assertTrue(filter.shouldNotFilter(ssoUrl));
    assertEquals(false, filter.shouldNotFilter(protectedApi));
  }

  @Test
  void shouldNotFilterRejectsUnexpectedMethodsForPublicAuthEndpoints() {
    final MockHttpServletRequest login = new MockHttpServletRequest("GET", "/api/auth/login");
    final MockHttpServletRequest register = new MockHttpServletRequest("GET", "/api/auth/register");
    final MockHttpServletRequest refresh = new MockHttpServletRequest("GET", "/api/auth/refresh");
    final MockHttpServletRequest ssoUrl =
        new MockHttpServletRequest("POST", "/api/auth/sso/google/url");

    assertFalse(filter.shouldNotFilter(login));
    assertFalse(filter.shouldNotFilter(register));
    assertFalse(filter.shouldNotFilter(refresh));
    assertFalse(filter.shouldNotFilter(ssoUrl));
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

    filter.doFilterInternal(request, response, chain);

    verify(chain).doFilter(request, response);
    verify(supabaseJwtService, never()).validateAccessToken(anyString());
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

    authenticateJwtWithPublicUserId(
        "valid-inactive",
        "sub-inactive",
        "inactive@example.com",
        "USER",
        "c1f84e7b-bb84-412d-81bb-4449df141f11");
    UserProfile inactive = new UserProfile();
    inactive.setId(UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11"));
    inactive.setSupabaseUserId("sub-inactive");
    inactive.setEmail("inactive@example.com");
    inactive.setRole("USER");
    inactive.setActive(false);

    when(tokenRevocationService.isRevoked("valid-inactive")).thenReturn(false);
    when(userProfileService.findByPublicUserId("c1f84e7b-bb84-412d-81bb-4449df141f11"))
        .thenReturn(Optional.of(inactive));

    filter.doFilterInternal(request, response, chain);

    assertEquals(401, response.getStatus());
    assertTrue(response.getContentAsString()
        .contains("Your account has been deactivated. Please contact an administrator."));
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void doFilterInternalUsesExistingJwtAuthenticationWithoutRevalidatingToken() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer existing-jwt-token");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    final Jwt jwt = jwt(
        "existing-jwt-token",
        "ctx-sub-2",
        "ctx2@example.com",
        "authenticated",
        "c1f84e7b-bb84-412d-81bb-4449df141f11");
    UserProfile admin = new UserProfile();
    admin.setId(UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11"));
    admin.setSupabaseUserId("ctx-sub-2");
    admin.setEmail("ctx2@example.com");
    admin.setRole("ADMIN");
    admin.setActive(true);

    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(
            jwt,
            null,
            List.of(new SimpleGrantedAuthority("ROLE_STUDENT"))));

    when(tokenRevocationService.isRevoked("existing-jwt-token")).thenReturn(false);
    when(userProfileService.findByPublicUserId("c1f84e7b-bb84-412d-81bb-4449df141f11"))
        .thenReturn(Optional.of(admin));

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(auth != null);
    assertTrue(auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())));
    verify(chain).doFilter(request, response);
    verify(supabaseJwtService, never()).validateAccessToken(anyString());
  }

  @Test
  void doFilterInternalAuthenticatesUsingTokenRoleWhenProfileAbsent() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-user");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    authenticateJwtWithPublicUserId(
        "valid-user",
        "sub-user",
        "user@example.com",
        "authenticated",
        "c1f84e7b-bb84-412d-81bb-4449df141f11");
    when(tokenRevocationService.isRevoked("valid-user")).thenReturn(false);
    when(userProfileService.findByPublicUserId("c1f84e7b-bb84-412d-81bb-4449df141f11"))
        .thenReturn(Optional.empty());

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(
        auth.getAuthorities().stream().anyMatch(a -> "ROLE_STUDENT".equals(a.getAuthority())));
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

    authenticateJwtWithPublicUserId(
        "valid-admin",
        "sub-admin",
        "admin@example.com",
        "USER",
        "c1f84e7b-bb84-412d-81bb-4449df141f11");
    UserProfile admin = new UserProfile();
    admin.setId(UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11"));
    admin.setSupabaseUserId("sub-admin");
    admin.setEmail("admin@example.com");
    admin.setRole("ADMIN");
    admin.setActive(true);

    when(tokenRevocationService.isRevoked("valid-admin")).thenReturn(false);
    when(userProfileService.findByPublicUserId("c1f84e7b-bb84-412d-81bb-4449df141f11"))
        .thenReturn(Optional.of(admin));

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())));
    verify(chain).doFilter(request, response);
  }

  @Test
  void doFilterInternalRejectsTokenWithoutPublicUserIdClaim() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-email");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    authenticateJwt("valid-email", " ", "fallback@example.com", "USER");
    when(tokenRevocationService.isRevoked("valid-email")).thenReturn(false);

    filter.doFilterInternal(request, response, chain);

    assertEquals(401, response.getStatus());
    assertTrue(response.getContentAsString().contains("Missing public user id claim"));
    verify(userProfileService, never()).findByPublicUserId(anyString());
    verify(userProfileService, never()).findBySupabaseUserId(anyString());
    verify(userProfileService, never()).findByEmail(anyString());
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void doFilterInternalPrefersPublicUserIdClaimWhenPresent() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-public-user-id");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);
    final UUID publicUserId = UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11");

    authenticateJwtWithPublicUserId(
        "valid-public-user-id",
        " ",
        " ",
        "USER",
        publicUserId.toString());
    UserProfile user = new UserProfile();
    user.setId(publicUserId);
    user.setSupabaseUserId("sub-public");
    user.setEmail("public@example.com");
    user.setRole("ADMIN");
    user.setActive(true);

    when(tokenRevocationService.isRevoked("valid-public-user-id")).thenReturn(false);
    when(userProfileService.findByPublicUserId(publicUserId.toString()))
        .thenReturn(Optional.of(user));

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(auth != null);
    assertTrue(auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())));
    verify(userProfileService).findByPublicUserId(publicUserId.toString());
    verify(userProfileService, never()).findBySupabaseUserId(anyString());
    verify(userProfileService, never()).findByEmail(anyString());
    verify(chain).doFilter(request, response);
  }

  @Test
  void doFilterInternalRejectsBlankIdentityWhenPublicUserIdIsMissing()
      throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-blank-role");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    authenticateJwt("valid-blank-role", " ", " ", " ");
    when(tokenRevocationService.isRevoked("valid-blank-role")).thenReturn(false);

    filter.doFilterInternal(request, response, chain);

    assertEquals(401, response.getStatus());
    assertTrue(response.getContentAsString().contains("Missing public user id claim"));
    verify(userProfileService, never()).findByPublicUserId(anyString());
    verify(userProfileService, never()).findBySupabaseUserId(anyString());
    verify(userProfileService, never()).findByEmail(anyString());
    verify(chain, never()).doFilter(request, response);
  }

  @Test
  void doFilterInternalFallsBackToTokenRoleWhenProfileRoleBlank() throws Exception {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users/me");
    request.addHeader("Authorization", "Bearer valid-blank-profile-role");
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final FilterChain chain = mock(FilterChain.class);

    authenticateJwtWithPublicUserId(
        "valid-blank-profile-role",
        "sub-role-fallback",
        "role@example.com",
        "authenticated",
        "c1f84e7b-bb84-412d-81bb-4449df141f11");
    UserProfile user = new UserProfile();
    user.setId(UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11"));
    user.setSupabaseUserId("sub-role-fallback");
    user.setEmail("role@example.com");
    user.setRole(" ");
    user.setActive(true);

    when(tokenRevocationService.isRevoked("valid-blank-profile-role")).thenReturn(false);
    when(userProfileService.findByPublicUserId("c1f84e7b-bb84-412d-81bb-4449df141f11"))
        .thenReturn(Optional.of(user));

    filter.doFilterInternal(request, response, chain);

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(auth != null);
    assertTrue(
        auth.getAuthorities().stream().anyMatch(a -> "ROLE_STUDENT".equals(a.getAuthority())));
    verify(chain).doFilter(request, response);
  }

  private Jwt jwt(String tokenValue, String sub, String email, String role) {
    return jwt(tokenValue, sub, email, role, null);
  }

  private Jwt jwt(String tokenValue, String sub, String email, String role, String publicUserId) {
    Map<String, Object> claims = new java.util.LinkedHashMap<>();
    claims.put("sub", sub);
    claims.put("email", email);
    claims.put("role", role);
    claims.put("aud", List.of("authenticated"));
    claims.put("iss", "https://supabase.test/auth/v1");
    if (publicUserId != null) {
      claims.put("yomu_user_id", publicUserId);
    }

    Instant now = Instant.now();
    return new Jwt(
        tokenValue,
        now,
        now.plusSeconds(3600),
        Map.of("alg", "none"),
        claims);
  }

  private void authenticateJwt(String tokenValue, String sub, String email, String role) {
    authenticateJwtWithPublicUserId(tokenValue, sub, email, role, null);
  }

  private void authenticateJwtWithPublicUserId(
      String tokenValue,
      String sub,
      String email,
      String role,
      String publicUserId) {
    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(
            jwt(tokenValue, sub, email, role, publicUserId),
            null,
            List.of(new SimpleGrantedAuthority("ROLE_STUDENT"))));
  }
}

