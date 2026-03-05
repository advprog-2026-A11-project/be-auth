package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private SupabaseJwtService supabaseJwtService;

  @MockBean
  private UserProfileService userProfileService;

  @Test
  void meWithoutTokenReturnsUnauthorized() throws Exception {
    mockMvc.perform(get("/api/auth/me"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  void meWithInvalidTokenReturnsUnauthorized() throws Exception {
    when(supabaseJwtService.validateAccessToken("bad-token"))
        .thenThrow(new SupabaseJwtService.InvalidTokenException("Invalid Supabase access token"));

    mockMvc.perform(get("/api/auth/me")
            .header("Authorization", "Bearer bad-token"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value(401));
  }

  @Test
  void meWithValidTokenReturnsOk() throws Exception {
    Instant now = Instant.now();
    Jwt jwt = new Jwt(
        "valid-token",
        now,
        now.plusSeconds(3600),
        Map.of("alg", "none"),
        Map.of(
            "sub", "supabase-user-1",
            "email", "user1@example.com",
            "role", "USER",
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));

    when(supabaseJwtService.validateAccessToken("valid-token")).thenReturn(jwt);

    UserProfile user = new UserProfile();
    user.setId(1L);
    user.setSupabaseUserId("supabase-user-1");
    user.setEmail("user1@example.com");
    user.setUsername("user1");
    user.setDisplayName("User One");
    user.setRole("USER");
    user.setActive(true);

    when(userProfileService.findBySupabaseUserId("supabase-user-1")).thenReturn(Optional.of(user));
    when(userProfileService.findByEmail("user1@example.com")).thenReturn(Optional.of(user));

    mockMvc.perform(get("/api/auth/me")
            .header("Authorization", "Bearer valid-token"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sub").value("supabase-user-1"))
        .andExpect(jsonPath("$.profile.supabaseUserId").value("supabase-user-1"));
  }
}
