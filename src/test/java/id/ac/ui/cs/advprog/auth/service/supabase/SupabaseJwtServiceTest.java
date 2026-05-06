package id.ac.ui.cs.advprog.auth.service.supabase;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class SupabaseJwtServiceTest {

  @Test
  void validateAccessTokenWithoutConfigThrows() {
    SupabaseJwtService svc = new SupabaseJwtService("", "", "authenticated", "");
    SupabaseJwtService.InvalidTokenException ex = assertThrows(
        SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("any"));
    String msg = ex.getMessage();
    assertTrue(msg.contains("SUPABASE_JWKS_URL")
        || msg.contains("Invalid Supabase"));
  }
}


