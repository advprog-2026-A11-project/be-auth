package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.LoginResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.auth.AuthLoginService;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
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

  @MockBean
  private SupabaseAuthClient supabaseAuthClient;

  @Test
  void loginUserSuccessReturnsOk() throws Exception {
    LoginResponse loginResponse = new LoginResponse(
        "access-user",
        "refresh-user",
        "Bearer",
        3600L,
        "535251d5-a941-49b0-9a04-5b26dc55ec61",
        "USER",
        "Login successful");

    when(authLoginService.login(eq("user@example.com"), eq("password123")))
        .thenReturn(loginResponse);

    mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"identifier\":\"user@example.com\",\"password\":\"password123\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userId").value("535251d5-a941-49b0-9a04-5b26dc55ec61"))
        .andExpect(jsonPath("$.role").value("USER"));
  }

  @Test
  void loginAdminSuccessReturnsOk() throws Exception {
    LoginResponse loginResponse = new LoginResponse(
        "access-admin",
        "refresh-admin",
        "Bearer",
        3600L,
        "a8df4b87-2d2c-4d7b-9cb9-e13cc298a3b8",
        "ADMIN",
        "Login successful");

    when(authLoginService.login(eq("admin@example.com"), eq("password123")))
        .thenReturn(loginResponse);

    mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"identifier\":\"admin@example.com\",\"password\":\"password123\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userId").value("a8df4b87-2d2c-4d7b-9cb9-e13cc298a3b8"))
        .andExpect(jsonPath("$.role").value("ADMIN"));
  }

  @Test
  void registerEndpointIsPublicAndReturnsCreated() throws Exception {
    LoginResponse registerResponse = new LoginResponse(
        "access-register",
        "refresh-register",
        "Bearer",
        3600L,
        "8aab73b9-1f18-4fc3-b645-5932daff10fa",
        "USER",
        "Registration successful");

    when(authLoginService.register(
        eq("new@example.com"),
        eq("password123"),
        eq("newuser"),
        eq("New User"))).thenReturn(registerResponse);

    mockMvc.perform(post("/api/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                "{\"email\":\"new@example.com\",\"password\":\"password123\","
                    + "\"username\":\"newuser\",\"displayName\":\"New User\"}"))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.userId").value("8aab73b9-1f18-4fc3-b645-5932daff10fa"))
        .andExpect(jsonPath("$.role").value("USER"));
  }

  @Test
  void refreshEndpointIsPublicAndReturnsOk() throws Exception {
    LoginResponse refreshResponse = new LoginResponse(
        "access-refresh",
        "refresh-next",
        "Bearer",
        3600L,
        "fca43fa7-2ad7-4357-9c6b-2df30224cffe",
        "USER",
        "Session refreshed");

    when(supabaseAuthClient.refreshSession(eq("refresh-valid")))
        .thenReturn(new SupabaseAuthClient.LoginResult(
            refreshResponse.accessToken(),
            refreshResponse.refreshToken(),
            refreshResponse.expiresIn(),
            "supabase-user-3",
            "refresh@example.com",
            refreshResponse.role()));
    UserProfile refreshedUser = new UserProfile();
    refreshedUser.setId(UUID.fromString("fca43fa7-2ad7-4357-9c6b-2df30224cffe"));
    refreshedUser.setSupabaseUserId("supabase-user-3");
    refreshedUser.setEmail("refresh@example.com");
    refreshedUser.setRole("USER");
    refreshedUser.setActive(true);
    when(userProfileService.upsertFromIdentity(
        "supabase-user-3",
        "refresh@example.com",
        "USER")).thenReturn(refreshedUser);

    mockMvc.perform(post("/api/auth/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"refreshToken\":\"refresh-valid\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").value("access-refresh"))
        .andExpect(jsonPath("$.refreshToken").value("refresh-next"))
        .andExpect(jsonPath("$.message").value("Session refreshed"));
  }

  @Test
  void logoutEndpointRevokesCurrentToken() throws Exception {
    Jwt jwt = validJwt(
        "token-logout",
        "supabase-user-4",
        "logout@example.com",
        "USER",
        "f3150ad7-cfde-4eeb-8eed-deebb8780780");
    when(supabaseJwtService.validateAccessToken("token-logout")).thenReturn(jwt);

    UserProfile user = new UserProfile();
    user.setId(UUID.fromString("f3150ad7-cfde-4eeb-8eed-deebb8780780"));
    user.setSupabaseUserId("supabase-user-4");
    user.setRole("USER");
    user.setEmail("logout@example.com");
    user.setActive(true);
    when(userProfileService.findByPublicUserId("f3150ad7-cfde-4eeb-8eed-deebb8780780"))
        .thenReturn(Optional.of(user));
    doNothing().when(supabaseAuthClient).logout("token-logout");

    mockMvc.perform(post("/api/auth/logout")
            .header("Authorization", "Bearer token-logout"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Logout successful"));

    mockMvc.perform(get("/api/auth/me")
            .header("Authorization", "Bearer token-logout"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Session has been revoked"));
  }

  @Test
  void adminRouteDeniedForUserRole() throws Exception {
    Jwt jwt = validJwt(
        "token-user",
        "supabase-user-1",
        "user@example.com",
        "USER",
        "78ba3c17-2dec-4eef-878f-fd326dcb8181");
    when(supabaseJwtService.validateAccessToken("token-user")).thenReturn(jwt);

    UserProfile user = new UserProfile();
    user.setId(UUID.fromString("78ba3c17-2dec-4eef-878f-fd326dcb8181"));
    user.setSupabaseUserId("supabase-user-1");
    user.setRole("USER");
    user.setEmail("user@example.com");
    when(userProfileService.findByPublicUserId("78ba3c17-2dec-4eef-878f-fd326dcb8181"))
        .thenReturn(Optional.of(user));

    mockMvc.perform(get("/api/admin/ping")
            .header("Authorization", "Bearer token-user"))
        .andExpect(status().isForbidden());
  }

  @Test
  void adminRouteAllowedForAdminRole() throws Exception {
    Jwt jwt = validJwt(
        "token-admin",
        "supabase-admin-1",
        "admin@example.com",
        "ADMIN",
        "a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106");
    when(supabaseJwtService.validateAccessToken("token-admin")).thenReturn(jwt);

    UserProfile admin = new UserProfile();
    admin.setId(UUID.fromString("cc0d1aa4-9a09-4f8b-b7f6-cb9c903d2fc7"));
    admin.setSupabaseUserId("supabase-admin-1");
    admin.setRole("ADMIN");
    admin.setEmail("admin@example.com");
    when(userProfileService.findByPublicUserId("a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106"))
        .thenReturn(Optional.of(admin));

    mockMvc.perform(get("/api/admin/ping")
            .header("Authorization", "Bearer token-admin"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Admin access granted"))
        .andExpect(jsonPath("$.userId").value("a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106"));
  }

  private Jwt validJwt(
      String tokenValue,
      String sub,
      String email,
      String userRole,
      String publicUserId) {
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
            "user_role", userRole,
            "yomu_user_id", publicUserId,
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));
  }
}

