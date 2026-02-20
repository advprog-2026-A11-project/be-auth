package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

class SupabaseJwtServiceDetailedTest {

  private SupabaseJwtService svc;

  @BeforeEach
  void setup() {
    svc = new SupabaseJwtService("https://supabase.test", "", "authenticated", "");
  }

  private void injectDecoder(JwtDecoder decoder) throws Exception {
    java.lang.reflect.Field f = SupabaseJwtService.class.getDeclaredField("jwtDecoder");
    f.setAccessible(true);
    f.set(svc, decoder);
  }

  @Test
  void validateAccessTokenSucceedsWhenClaimsValid() throws Exception {
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getClaimAsString("email")).thenReturn("a@b");
    when(jwt.getSubject()).thenReturn("sub");
    when(jwt.getClaimAsString("role")).thenReturn("USER");
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("https://supabase.test/auth/v1"));
    when(decoder.decode("token-ok")).thenReturn(jwt);
    injectDecoder(decoder);

    Jwt out = svc.validateAccessToken("token-ok");
    assertNotNull(out);
    assertEquals("sub", out.getSubject());
  }

  @Test
  void validateAccessTokenThrowsOnExpired() throws Exception {
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(Instant.now().minusSeconds(10));
    when(decoder.decode("token-expired")).thenReturn(jwt);
    injectDecoder(decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("token-expired"));
    assertTrue(ex.getMessage().toLowerCase().contains("expired"));
  }

  @Test
  void validateAccessTokenThrowsOnIssuerMismatch() throws Exception {
    // Create service with configured issuer
    svc = new SupabaseJwtService("https://supabase.test", "https://good-issuer/", "authenticated", "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(1000));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("http://other-issuer/"));
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(decoder.decode("tkn")).thenReturn(jwt);
    injectDecoder(decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("tkn"));
    assertTrue(ex.getMessage().toLowerCase().contains("issuer"));
  }

  @Test
  void validateAccessTokenThrowsOnAudienceMismatch() throws Exception {
    svc = new SupabaseJwtService("https://supabase.test", "", "expected-aud", "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(1000));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("https://supabase.test/auth/v1"));
    when(jwt.getAudience()).thenReturn(List.of("other-aud"));
    when(decoder.decode("tkn2")).thenReturn(jwt);
    injectDecoder(decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("tkn2"));
    assertTrue(ex.getMessage().toLowerCase().contains("audience"));
  }
}
