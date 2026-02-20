package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

class SupabaseJwtServiceReflectionTest {

  @Test
  void trimTrailingSlashVariants() throws Exception {
    SupabaseJwtService svc = new SupabaseJwtService("", "", "aud", "http://jwks");
    Method m = SupabaseJwtService.class.getDeclaredMethod("trimTrailingSlash", String.class);
    m.setAccessible(true);
    assertNull(m.invoke(svc, (Object) null));
    assertEquals("", m.invoke(svc, ""));
    assertEquals("http://a", m.invoke(svc, "http://a/"));
    assertEquals("http://a/b", m.invoke(svc, "http://a/b"));
  }

  @Test
  void resolveIssuerAndJwksUrlProduceExpected() throws Exception {
    SupabaseJwtService svc = new SupabaseJwtService("https://supabase.test/", "", "aud", "");
    Method resolveIssuer = SupabaseJwtService.class.getDeclaredMethod("resolveIssuer");
    Method resolveJwks = SupabaseJwtService.class.getDeclaredMethod("resolveJwksUrl");
    resolveIssuer.setAccessible(true);
    resolveJwks.setAccessible(true);
    String iss = (String) resolveIssuer.invoke(svc);
    String jwks = (String) resolveJwks.invoke(svc);
    assertEquals("https://supabase.test/auth/v1", iss);
    assertEquals("https://supabase.test/auth/v1/.well-known/jwks.json", jwks);
  }

  @Test
  void getOrCreateDecoderReturnsSameInstance() throws Exception {
    // Supply a jwks-url so build path uses it directly
    SupabaseJwtService svc = new SupabaseJwtService("", "", "aud", "https://example.com/jwks.json");
    Method getOrCreate = SupabaseJwtService.class.getDeclaredMethod("getOrCreateDecoder");
    getOrCreate.setAccessible(true);
    Object d1 = getOrCreate.invoke(svc);
    Object d2 = getOrCreate.invoke(svc);
    assertNotNull(d1);
    assertSame(d1, d2);
  }
}
