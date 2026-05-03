package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
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
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
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
    user.setId(UUID.randomUUID());
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
        .andExpect(jsonPath("$.profile.role").value("STUDENT"));
  }

  @Test
  void meReturnsServiceUnavailableWhenProfileLookupFails() throws Exception {
    when(supabaseJwtService.validateAccessToken("db-error-token"))
        .thenReturn(jwt("db-error-token", "supabase-user-err", "err@example.com"));
    when(userProfileService.findBySupabaseUserId("supabase-user-err"))
        .thenThrow(new DataAccessResourceFailureException("db down"));

    mockMvc.perform(get("/api/auth/me")
            .header("Authorization", "Bearer db-error-token"))
        .andExpect(status().isServiceUnavailable())
        .andExpect(jsonPath("$.status").value(503))
        .andExpect(
            jsonPath("$.message").value(
                "Database unavailable. Check Supabase DB host/connection."));
  }

  @Test
  void usersCollectionWithUserRoleReturnsForbidden() throws Exception {
    when(supabaseJwtService.validateAccessToken("user-token"))
        .thenReturn(jwt("user-token", "supabase-user-2", "user2@example.com"));
    when(userProfileService.findBySupabaseUserId("supabase-user-2"))
        .thenReturn(Optional.of(userProfile("supabase-user-2", "user2@example.com", "USER")));

    mockMvc.perform(get("/api/users")
            .header("Authorization", "Bearer user-token"))
        .andExpect(status().isForbidden());
  }

  @Test
  void createUserWithUserRoleReturnsForbidden() throws Exception {
    when(supabaseJwtService.validateAccessToken("user-token"))
        .thenReturn(jwt("user-token", "supabase-user-2", "user2@example.com"));
    when(userProfileService.findBySupabaseUserId("supabase-user-2"))
        .thenReturn(Optional.of(userProfile("supabase-user-2", "user2@example.com", "USER")));

    mockMvc.perform(post("/api/users")
            .header("Authorization", "Bearer user-token")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                "{\"username\":\"new-user\",\"email\":\"new@example.com\","
                    + "\"displayName\":\"New User\",\"role\":\"USER\"}"))
        .andExpect(status().isForbidden());
  }

  @Test
  void getUserByIdWithUserRoleReturnsForbidden() throws Exception {
    // Arrange
    when(supabaseJwtService.validateAccessToken("user-token"))
        .thenReturn(jwt("user-token", "supabase-user-2", "user2@example.com"));
    when(userProfileService.findBySupabaseUserId("supabase-user-2"))
        .thenReturn(Optional.of(userProfile("supabase-user-2", "user2@example.com", "USER")));

    // Act + Assert
    mockMvc.perform(get("/api/users/" + UUID.randomUUID())
            .header("Authorization", "Bearer user-token"))
        .andExpect(status().isForbidden());
  }

  @Test
  void deleteUserByIdWithUserRoleReturnsForbidden() throws Exception {
    // Arrange
    when(supabaseJwtService.validateAccessToken("user-token"))
        .thenReturn(jwt("user-token", "supabase-user-2", "user2@example.com"));
    when(userProfileService.findBySupabaseUserId("supabase-user-2"))
        .thenReturn(Optional.of(userProfile("supabase-user-2", "user2@example.com", "USER")));

    // Act + Assert
    mockMvc.perform(delete("/api/users/" + UUID.randomUUID())
            .header("Authorization", "Bearer user-token"))
        .andExpect(status().isForbidden());
  }

  @Test
  void usersCollectionWithAdminRoleReturnsOk() throws Exception {
    when(supabaseJwtService.validateAccessToken("admin-token"))
        .thenReturn(jwt("admin-token", "supabase-admin-1", "admin@example.com"));
    when(userProfileService.findBySupabaseUserId("supabase-admin-1"))
        .thenReturn(Optional.of(userProfile("supabase-admin-1", "admin@example.com", "ADMIN")));
    when(userProfileService.findAll())
        .thenReturn(List.of(userProfile("supabase-user-3", "user3@example.com", "USER")));

    mockMvc.perform(get("/api/users")
            .header("Authorization", "Bearer admin-token"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].email").value("user3@example.com"));
  }

  @Test
  void getUserByIdWithAdminRoleReturnsOk() throws Exception {
    UUID id = UUID.randomUUID();
    // Arrange
    when(supabaseJwtService.validateAccessToken("admin-token"))
        .thenReturn(jwt("admin-token", "supabase-admin-1", "admin@example.com"));
    when(userProfileService.findBySupabaseUserId("supabase-admin-1"))
        .thenReturn(Optional.of(userProfile("supabase-admin-1", "admin@example.com", "ADMIN")));
    when(userProfileService.findById(id))
        .thenReturn(Optional.of(userProfile("supabase-user-7", "user7@example.com", "USER")));

    // Act + Assert
    mockMvc.perform(get("/api/users/" + id)
            .header("Authorization", "Bearer admin-token"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").exists())
        .andExpect(jsonPath("$.email").value("user7@example.com"));
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

  private UserProfile userProfile(String supabaseUserId, String email, String role) {
    UserProfile user = new UserProfile();
    user.setId(UUID.randomUUID());
    user.setSupabaseUserId(supabaseUserId);
    user.setEmail(email);
    user.setUsername(email);
    user.setDisplayName(role + " User");
    user.setRole(role);
    user.setActive(true);
    return user;
  }
}

