package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.AuthSessionService;
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
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class ChangePasswordIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private AuthSessionService authSessionService;

  @MockBean
  private SupabaseJwtService supabaseJwtService;

  @MockBean
  private UserProfileService userProfileService;

  @Test
  void changePasswordSuccessReturnsOk() throws Exception {
    when(supabaseJwtService.validateAccessToken("token-password"))
        .thenReturn(jwt("token-password", "sub-password", "password@example.com"));

    UserProfile active = new UserProfile();
    active.setSupabaseUserId("sub-password");
    active.setEmail("password@example.com");
    active.setRole("USER");
    active.setActive(true);
    when(userProfileService.findBySupabaseUserId("sub-password")).thenReturn(Optional.of(active));
    doNothing().when(authSessionService).changePassword(
        eq("token-password"),
        eq("password@example.com"),
        eq("current-password"),
        eq("new-password"));

    mockMvc.perform(post("/api/auth/change-password")
            .header("Authorization", "Bearer token-password")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                """
                {
                  "currentPassword": "current-password",
                  "newPassword": "new-password"
                }
                """))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Password changed"));
  }

  @Test
  void changePasswordWrongCurrentPasswordReturnsUnauthorized() throws Exception {
    when(supabaseJwtService.validateAccessToken("token-password"))
        .thenReturn(jwt("token-password", "sub-password", "password@example.com"));

    UserProfile active = new UserProfile();
    active.setSupabaseUserId("sub-password");
    active.setEmail("password@example.com");
    active.setRole("USER");
    active.setActive(true);
    when(userProfileService.findBySupabaseUserId("sub-password")).thenReturn(Optional.of(active));
    doThrow(new UnauthorizedException("Invalid login credentials"))
        .when(authSessionService)
        .changePassword(
            eq("token-password"),
            eq("password@example.com"),
            eq("wrong-password"),
            eq("new-password"));

    mockMvc.perform(post("/api/auth/change-password")
            .header("Authorization", "Bearer token-password")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                """
                {
                  "currentPassword": "wrong-password",
                  "newPassword": "new-password"
                }
                """))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Invalid login credentials"));
  }

  @Test
  void changePasswordShortNewPasswordReturnsBadRequest() throws Exception {
    when(supabaseJwtService.validateAccessToken("token-password"))
        .thenReturn(jwt("token-password", "sub-password", "password@example.com"));

    UserProfile active = new UserProfile();
    active.setSupabaseUserId("sub-password");
    active.setEmail("password@example.com");
    active.setRole("USER");
    active.setActive(true);
    when(userProfileService.findBySupabaseUserId("sub-password")).thenReturn(Optional.of(active));

    mockMvc.perform(post("/api/auth/change-password")
            .header("Authorization", "Bearer token-password")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                """
                {
                  "currentPassword": "current-password",
                  "newPassword": "short"
                }
                """))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.validationErrors.newPassword").exists());
  }

  private Jwt jwt(String tokenValue, String sub, String email) {
    Instant now = Instant.now();
    return new Jwt(
        tokenValue,
        now,
        now.plusSeconds(3600),
        Map.of("alg", "none"),
        Map.of(
            "sub", sub,
            "email", email,
            "role", "authenticated",
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));
  }
}
