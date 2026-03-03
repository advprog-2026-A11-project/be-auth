package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.AuthLoginService;
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
class LoginAndAdminFlowIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private AuthLoginService authLoginService;

  @MockBean
  private SupabaseJwtService supabaseJwtService;

  @MockBean
  private UserProfileService userProfileService;

  @Test
  void loginUserSuccessReturnsOk() throws Exception {
    LoginResponse loginResponse = new LoginResponse(
        "access-user",
        "refresh-user",
        "Bearer",
        3600L,
        "supabase-user-1",
        "USER",
        "Login successful");

    when(authLoginService.login(eq("user@example.com"), eq("password123")))
        .thenReturn(loginResponse);

    mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"identifier\":\"user@example.com\",\"password\":\"password123\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userId").value("supabase-user-1"))
        .andExpect(jsonPath("$.role").value("USER"));
  }

  @Test
  void loginAdminSuccessReturnsOk() throws Exception {
    LoginResponse loginResponse = new LoginResponse(
        "access-admin",
        "refresh-admin",
        "Bearer",
        3600L,
        "supabase-admin-1",
        "ADMIN",
        "Login successful");

    when(authLoginService.login(eq("admin@example.com"), eq("password123")))
        .thenReturn(loginResponse);

    mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"identifier\":\"admin@example.com\",\"password\":\"password123\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userId").value("supabase-admin-1"))
        .andExpect(jsonPath("$.role").value("ADMIN"));
  }

  @Test
  void adminRouteDeniedForUserRole() throws Exception {
    Jwt jwt = validJwt("token-user", "supabase-user-1", "user@example.com");
    when(supabaseJwtService.validateAccessToken("token-user")).thenReturn(jwt);

    UserProfile user = new UserProfile();
    user.setSupabaseUserId("supabase-user-1");
    user.setRole("USER");
    user.setEmail("user@example.com");
    when(userProfileService.findBySupabaseUserId("supabase-user-1")).thenReturn(Optional.of(user));
    when(userProfileService.findByEmail("user@example.com")).thenReturn(Optional.of(user));

    mockMvc.perform(get("/api/admin/ping")
            .header("Authorization", "Bearer token-user"))
        .andExpect(status().isForbidden());
  }

  @Test
  void adminRouteAllowedForAdminRole() throws Exception {
    Jwt jwt = validJwt("token-admin", "supabase-admin-1", "admin@example.com");
    when(supabaseJwtService.validateAccessToken("token-admin")).thenReturn(jwt);

    UserProfile admin = new UserProfile();
    admin.setSupabaseUserId("supabase-admin-1");
    admin.setRole("ADMIN");
    admin.setEmail("admin@example.com");
    when(userProfileService.findBySupabaseUserId("supabase-admin-1"))
        .thenReturn(Optional.of(admin));
    when(userProfileService.findByEmail("admin@example.com")).thenReturn(Optional.of(admin));

    mockMvc.perform(get("/api/admin/ping")
            .header("Authorization", "Bearer token-admin"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Admin access granted"))
        .andExpect(jsonPath("$.userId").value("supabase-admin-1"));
  }

  private Jwt validJwt(String tokenValue, String sub, String email) {
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
