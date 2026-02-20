package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class SupabaseJwtServiceTest {

  @Test
  void validateAccessTokenWithoutConfigThrows() {
    SupabaseJwtService svc = new SupabaseJwtService("", "", "authenticated", "");
    SupabaseJwtService.InvalidTokenException ex = assertThrows(
        SupabaseJwtService.InvalidTokenException.class,
        () -> svc.validateAccessToken("any"));
    assertTrue(ex.getMessage().contains("SUPABASE_JWKS_URL") || ex.getMessage().contains("Invalid Supabase"));
  }
}
