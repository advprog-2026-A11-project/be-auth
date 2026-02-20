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
    SupabaseJwtService svc = new SupabaseJwtService("https://supabase.test", "", "authenticated", "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    when(decoder.decode("bad-token")).thenThrow(new JwtException("decode failure"));
    injectDecoder(svc, decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("bad-token"));
    assertNotNull(ex.getCause());
    assertTrue(ex.getCause() instanceof JwtException);
  }

  @Test
  void resolveJwksUrlThrowsWhenNoConfig() throws Exception {
    SupabaseJwtService svc = new SupabaseJwtService("", "", "aud", "");
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
    SupabaseJwtService svc = new SupabaseJwtService("https://supabase.test", "", "expected-aud", "");
    JwtDecoder decoder = mock(JwtDecoder.class);
    Jwt jwt = mock(Jwt.class);
    when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));
    when(jwt.getIssuer()).thenReturn(new java.net.URL("https://supabase.test/auth/v1"));
    when(jwt.getAudience()).thenReturn(null);
    when(decoder.decode("tkn-null-aud")).thenReturn(jwt);
    injectDecoder(svc, decoder);

    SupabaseJwtService.InvalidTokenException ex = assertThrows(SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("tkn-null-aud"));
    assertTrue(ex.getMessage().toLowerCase().contains("audience"));
  }
}
