package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

class SupabaseJwtServiceExtraTest {

  private void injectDecoder(SupabaseJwtService svc, JwtDecoder decoder) throws Exception {
    java.lang.reflect.Field f = SupabaseJwtService.class.getDeclaredField("jwtDecoder");
    f.setAccessible(true);
    f.set(svc, decoder);
  }

  @Test
  void validateAccessTokenWrapsJwtExceptionWithCause() throws Exception {
    final SupabaseJwtService svc = new SupabaseJwtService(
        "https://supabase.test",
        "",
        "authenticated",
        "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    when(decoder.decode("bad-token"))
        .thenThrow(new JwtException("decode failure"));
    injectDecoder(svc, decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(
        SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("bad-token"));
    assertNotNull(ex.getCause());
    assertTrue(ex.getCause() instanceof JwtException);
  }

  @Test
  void resolveJwksUrlThrowsWhenNoConfig() throws Exception {
    final SupabaseJwtService svc = new SupabaseJwtService("", "", "aud", "");
    java.lang.reflect.Method m = SupabaseJwtService.class.getDeclaredMethod("resolveJwksUrl");
    m.setAccessible(true);
    try {
      m.invoke(svc);
      fail("expected InvalidTokenException");
    } catch (java.lang.reflect.InvocationTargetException ite) {
      Throwable cause = ite.getCause();
      assertNotNull(cause);
      assertTrue(cause instanceof SupabaseJwtService.InvalidTokenException);
      String msg = cause.getMessage().toLowerCase();
      assertTrue(msg.contains("jwks_url") || msg.contains("supabase"));
    }
  }

  @Test
  void validateAccessTokenThrowsWhenAudienceIsNull() throws Exception {
    final SupabaseJwtService svc = new SupabaseJwtService(
        "https://supabase.test",
        "",
        "expected-aud",
        "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("https://supabase.test/auth/v1"));
    when(jwt.getAudience()).thenReturn(null);
    when(decoder.decode("tkn-null-aud"))
        .thenReturn(jwt);
    injectDecoder(svc, decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(
        SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("tkn-null-aud"));
    assertTrue(ex.getMessage().toLowerCase().contains("audience"));
  }

  @Test
  void validateAccessTokenThrowsWhenExpirationIsMissing() throws Exception {
    final SupabaseJwtService svc = new SupabaseJwtService(
        "https://supabase.test",
        "",
        "authenticated",
        "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(null);
    when(decoder.decode("tkn-no-exp")).thenReturn(jwt);
    injectDecoder(svc, decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(
        SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("tkn-no-exp"));
    assertTrue(ex.getMessage().toLowerCase().contains("expired"));
  }

  @Test
  void validateAccessTokenThrowsWhenIssuerIsMissing() throws Exception {
    final SupabaseJwtService svc = new SupabaseJwtService(
        "https://supabase.test",
        "https://supabase.test/auth/v1",
        "authenticated",
        "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));
    when(jwt.getIssuer()).thenReturn(null);
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(decoder.decode("tkn-no-issuer")).thenReturn(jwt);
    injectDecoder(svc, decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(
        SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("tkn-no-issuer"));
    assertTrue(ex.getMessage().toLowerCase().contains("issuer"));
  }

  @Test
  void validateAccessTokenSkipsAudienceCheckWhenAudienceExpectationBlank() throws Exception {
    final SupabaseJwtService svc = new SupabaseJwtService(
        "https://supabase.test",
        "",
        "",
        "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("https://supabase.test/auth/v1"));
    when(jwt.getAudience()).thenReturn(null);
    when(decoder.decode("tkn-no-aud-check")).thenReturn(jwt);
    injectDecoder(svc, decoder);

    Jwt validated = svc.validateAccessToken("tkn-no-aud-check");
    assertSame(jwt, validated);
  }

  @Test
  void validateAccessTokenSkipsIssuerCheckWhenIssuerExpectationBlank() throws Exception {
    final SupabaseJwtService svc = new SupabaseJwtService(
        "",
        "",
        "authenticated",
        "https://example.com/jwks.json");
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));
    when(jwt.getIssuer()).thenReturn(null);
    when(jwt.getAudience()).thenReturn(List.of("authenticated"));
    when(decoder.decode("tkn-no-issuer-check")).thenReturn(jwt);
    injectDecoder(svc, decoder);

    Jwt validated = svc.validateAccessToken("tkn-no-issuer-check");
    assertSame(jwt, validated);
  }
}
