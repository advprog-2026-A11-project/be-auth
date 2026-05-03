package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.service.auth.SupabaseGoogleSsoService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
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
    when(googleSsoService.createSsoUrl(null))
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

}

