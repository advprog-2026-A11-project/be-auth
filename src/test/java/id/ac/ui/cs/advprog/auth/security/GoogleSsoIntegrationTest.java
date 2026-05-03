package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.service.auth.SupabaseGoogleSsoService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class GoogleSsoIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private SupabaseGoogleSsoService googleSsoService;

  @Test
  void googleSsoUrlReturnsOk() throws Exception {
    when(googleSsoService.createSsoUrl())
        .thenReturn(new SsoUrlResponse(
            "google",
            "https://supabase.test/auth/v1/authorize?provider=google",
            "Google SSO URL generated"));

    mockMvc.perform(get("/api/auth/sso/google/url"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.provider").value("google"))
        .andExpect(
            jsonPath("$.authorizationUrl")
                .value("https://supabase.test/auth/v1/authorize?provider=google"));
  }

  @Test
  void googleSsoCallbackValidReturnsOk() throws Exception {
    when(googleSsoService.handleCallback(org.mockito.ArgumentMatchers.any()))
        .thenReturn(new SsoCallbackResponse(
            "access-token",
            "refresh-token",
            "535251d5-a941-49b0-9a04-5b26dc55ec61",
            true,
            "Google SSO login successful"));

    mockMvc.perform(post("/api/auth/sso/google/callback")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"code\":\"oauth-code\",\"state\":\"opaque-state\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userId").value("535251d5-a941-49b0-9a04-5b26dc55ec61"))
        .andExpect(jsonPath("$.linked").value(true));
  }

  @Test
  void googleSsoCallbackInvalidReturnsUnauthorized() throws Exception {
    when(googleSsoService.handleCallback(org.mockito.ArgumentMatchers.any()))
        .thenThrow(new UnauthorizedException("Invalid SSO callback code"));

    mockMvc.perform(post("/api/auth/sso/google/callback")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"code\":\"bad-code\",\"state\":\"expired-state\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Invalid SSO callback code"));
  }
}

