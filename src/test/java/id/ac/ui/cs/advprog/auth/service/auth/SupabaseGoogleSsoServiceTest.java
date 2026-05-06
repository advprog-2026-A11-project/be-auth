package id.ac.ui.cs.advprog.auth.service.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoUrlResponse;
import org.junit.jupiter.api.Test;

class SupabaseGoogleSsoServiceTest {

  private static final String CALLBACK_URL = "http://localhost:3000/users/account";

  private final SupabaseGoogleSsoService service = new SupabaseGoogleSsoService(
      "https://ubsiynttkoqzdcxpxzbg.supabase.co",
      "https://app.yomu.id/auth/callback");

  @Test
  void createSsoUrlDoesNotUseBackendPkceParameters() {
    SsoUrlResponse response = service.createSsoUrl(CALLBACK_URL);

    assertEquals("google", response.provider());
    assertFalse(response.authorizationUrl().contains("code_challenge"));
    assertFalse(response.authorizationUrl().contains("code_challenge_method"));
    assertFalse(response.authorizationUrl().contains("app_state"));
  }
}


