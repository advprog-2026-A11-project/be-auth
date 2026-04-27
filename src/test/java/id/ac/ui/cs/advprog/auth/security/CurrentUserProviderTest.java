package id.ac.ui.cs.advprog.auth.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class CurrentUserProviderTest {

  private final CurrentUserProvider currentUserProvider = new CurrentUserProvider();

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void getCurrentUserReturnsEmptyWhenAuthenticationMissing() {
    assertTrue(currentUserProvider.getCurrentUser().isEmpty());
  }

  @Test
  void getCurrentUserReadsAuthenticatedUserPrincipal() {
    SecurityContextHolder.getContext().setAuthentication(
        new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            new AuthenticatedUserPrincipal("sub-123", "user@example.com", "ADMIN"),
            null,
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));

    var currentUser = currentUserProvider.getCurrentUser();

    assertTrue(currentUser.isPresent());
    assertEquals("sub-123", currentUser.get().sub());
    assertEquals("user@example.com", currentUser.get().email());
    assertEquals("ADMIN", currentUser.get().role());
  }

  @Test
  void getCurrentUserReadsJwtAuthenticationToken() {
    Jwt jwt = new Jwt(
        "token-value",
        Instant.now(),
        Instant.now().plusSeconds(600),
        Map.of("alg", "none"),
        Map.of(
            "sub", "jwt-sub-123",
            "email", "jwt@example.com",
            "role", "authenticated"));

    SecurityContextHolder.getContext().setAuthentication(
        new UsernamePasswordAuthenticationToken(
            jwt,
            null,
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));

    var currentUser = currentUserProvider.getCurrentUser();

    assertTrue(currentUser.isPresent());
    assertEquals("jwt-sub-123", currentUser.get().sub());
    assertEquals("jwt@example.com", currentUser.get().email());
    assertEquals("ADMIN", currentUser.get().role());
  }

  @Test
  void getCurrentUserIgnoresUnsupportedPrincipalType() {
    SecurityContextHolder.getContext().setAuthentication(
        new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            "plain-string-principal",
            null));

    assertFalse(currentUserProvider.getCurrentUser().isPresent());
  }
}
