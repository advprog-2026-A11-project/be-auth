package id.ac.ui.cs.advprog.auth.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class CurrentUserProviderTest {

  private final CurrentUserProvider provider = new CurrentUserProvider();

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void getCurrentJwtReturnsEmptyWithoutAuthentication() {
    assertTrue(provider.getCurrentJwt().isEmpty());
    assertTrue(provider.getCurrentUser().isEmpty());
  }

  @Test
  void getCurrentUserReturnsPrincipalWhenAlreadyResolved() {
    AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-123", "user@example.com", "ADMIN");
    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(principal, null, List.of()));

    Optional<AuthenticatedUserPrincipal> currentUser = provider.getCurrentUser();

    assertTrue(currentUser.isPresent());
    assertEquals(principal, currentUser.get());
  }

  @Test
  void getCurrentUserBuildsPrincipalFromJwtClaimsAndAuthorities() {
    Jwt jwt = jwt("token-1", "sub-234", "jwt@example.com", "authenticated");
    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(
            jwt,
            null,
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));

    Optional<AuthenticatedUserPrincipal> currentUser = provider.getCurrentUser();

    assertTrue(currentUser.isPresent());
    assertEquals("sub-234", currentUser.get().sub());
    assertEquals("jwt@example.com", currentUser.get().email());
    assertEquals("ADMIN", currentUser.get().role());
    assertEquals("c1f84e7b-bb84-412d-81bb-4449df141f11", currentUser.get().publicUserId());
    assertTrue(provider.getCurrentJwt().isPresent());
  }

  @Test
  void getCurrentUserFallsBackToJwtCredentialsWhenPrincipalIsNotJwt() {
    Jwt jwt = jwt("token-2", "sub-345", "cred@example.com", "authenticated");
    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(
            "principal-name",
            jwt,
            List.of(new SimpleGrantedAuthority("ROLE_STUDENT"))));

    Optional<AuthenticatedUserPrincipal> currentUser = provider.getCurrentUser();

    assertTrue(currentUser.isPresent());
    assertEquals("sub-345", currentUser.get().sub());
    assertEquals("cred@example.com", currentUser.get().email());
    assertEquals("STUDENT", currentUser.get().role());
    assertTrue(provider.getCurrentJwt().isPresent());
  }

  @Test
  void getCurrentUserFallsBackToClaimRoleWhenAuthorityIsMissing() {
    Jwt jwt = jwt("token-3", "sub-456", "claim@example.com", "admin");
    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(jwt, null, List.of()));

    Optional<AuthenticatedUserPrincipal> currentUser = provider.getCurrentUser();

    assertTrue(currentUser.isPresent());
    assertEquals("ADMIN", currentUser.get().role());
  }

  @Test
  void requireCurrentUserThrowsWhenAuthenticationMissing() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        provider::requireCurrentUser);

    assertEquals("No authenticated user in security context", ex.getMessage());
    assertFalse(provider.getCurrentJwt().isPresent());
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
            "yomu_user_id", "c1f84e7b-bb84-412d-81bb-4449df141f11",
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));
  }
}

