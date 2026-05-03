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
            "yomu_user_id", "78ba3c17-2dec-4eef-878f-fd326dcb8181",
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));

    when(supabaseJwtService.validateAccessToken("valid-token")).thenReturn(jwt);

    UserProfile user = new UserProfile();
    user.setId(UUID.fromString("78ba3c17-2dec-4eef-878f-fd326dcb8181"));
    user.setSupabaseUserId("supabase-user-1");
    user.setEmail("user1@example.com");
    user.setUsername("user1");
    user.setDisplayName("User One");
    user.setRole("USER");
    user.setActive(true);

    when(userProfileService.findByPublicUserId("78ba3c17-2dec-4eef-878f-fd326dcb8181"))
        .thenReturn(Optional.of(user));

    mockMvc.perform(get("/api/auth/me")
            .header("Authorization", "Bearer valid-token"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sub").value("supabase-user-1"))
        .andExpect(jsonPath("$.profile.role").value("STUDENT"));
  }

  @Test
  void meReturnsServiceUnavailableWhenProfileLookupFails() throws Exception {
    when(supabaseJwtService.validateAccessToken("db-error-token"))
        .thenReturn(jwt(
            "db-error-token",
            "supabase-user-err",
            "err@example.com",
            "c1f84e7b-bb84-412d-81bb-4449df141f11"));
    when(userProfileService.findByPublicUserId("c1f84e7b-bb84-412d-81bb-4449df141f11"))
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
        .thenReturn(jwt(
            "user-token",
            "supabase-user-2",
            "user2@example.com",
            "6e3fee90-5fc5-4c06-a7ae-a382cccf36ac"));
    when(userProfileService.findByPublicUserId("6e3fee90-5fc5-4c06-a7ae-a382cccf36ac"))
        .thenReturn(Optional.of(userProfile(
            "6e3fee90-5fc5-4c06-a7ae-a382cccf36ac",
            "supabase-user-2",
            "user2@example.com",
            "USER")));

    mockMvc.perform(get("/api/users")
            .header("Authorization", "Bearer user-token"))
        .andExpect(status().isForbidden());
  }

  @Test
  void createUserWithUserRoleReturnsForbidden() throws Exception {
    when(supabaseJwtService.validateAccessToken("user-token"))
        .thenReturn(jwt(
            "user-token",
            "supabase-user-2",
            "user2@example.com",
            "6e3fee90-5fc5-4c06-a7ae-a382cccf36ac"));
    when(userProfileService.findByPublicUserId("6e3fee90-5fc5-4c06-a7ae-a382cccf36ac"))
        .thenReturn(Optional.of(userProfile(
            "6e3fee90-5fc5-4c06-a7ae-a382cccf36ac",
            "supabase-user-2",
            "user2@example.com",
            "USER")));

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
        .thenReturn(jwt(
            "user-token",
            "supabase-user-2",
            "user2@example.com",
            "6e3fee90-5fc5-4c06-a7ae-a382cccf36ac"));
    when(userProfileService.findByPublicUserId("6e3fee90-5fc5-4c06-a7ae-a382cccf36ac"))
        .thenReturn(Optional.of(userProfile(
            "6e3fee90-5fc5-4c06-a7ae-a382cccf36ac",
            "supabase-user-2",
            "user2@example.com",
            "USER")));

    // Act + Assert
    mockMvc.perform(get("/api/users/" + UUID.randomUUID())
            .header("Authorization", "Bearer user-token"))
        .andExpect(status().isForbidden());
  }

  @Test
  void deleteUserByIdWithUserRoleReturnsForbidden() throws Exception {
    // Arrange
    when(supabaseJwtService.validateAccessToken("user-token"))
        .thenReturn(jwt(
            "user-token",
            "supabase-user-2",
            "user2@example.com",
            "6e3fee90-5fc5-4c06-a7ae-a382cccf36ac"));
    when(userProfileService.findByPublicUserId("6e3fee90-5fc5-4c06-a7ae-a382cccf36ac"))
        .thenReturn(Optional.of(userProfile(
            "6e3fee90-5fc5-4c06-a7ae-a382cccf36ac",
            "supabase-user-2",
            "user2@example.com",
            "USER")));

    // Act + Assert
    mockMvc.perform(delete("/api/users/" + UUID.randomUUID())
            .header("Authorization", "Bearer user-token"))
        .andExpect(status().isForbidden());
  }

  @Test
  void usersCollectionWithAdminRoleReturnsOk() throws Exception {
    when(supabaseJwtService.validateAccessToken("admin-token"))
        .thenReturn(jwt(
            "admin-token",
            "supabase-admin-1",
            "admin@example.com",
            "a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106"));
    when(userProfileService.findByPublicUserId("a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106"))
        .thenReturn(Optional.of(userProfile(
            "a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106",
            "supabase-admin-1",
            "admin@example.com",
            "ADMIN")));
    when(userProfileService.findAll())
        .thenReturn(List.of(userProfile(
            "78ba3c17-2dec-4eef-878f-fd326dcb8181",
            "supabase-user-3",
            "user3@example.com",
            "USER")));

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
        .thenReturn(jwt(
            "admin-token",
            "supabase-admin-1",
            "admin@example.com",
            "a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106"));
    when(userProfileService.findByPublicUserId("a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106"))
        .thenReturn(Optional.of(userProfile(
            "a5a45e5e-ee42-446f-9a6e-3c2d3dd9c106",
            "supabase-admin-1",
            "admin@example.com",
            "ADMIN")));
    when(userProfileService.findById(id))
        .thenReturn(Optional.of(userProfile(
            "c1f84e7b-bb84-412d-81bb-4449df141f11",
            "supabase-user-7",
            "user7@example.com",
            "USER")));

    // Act + Assert
    mockMvc.perform(get("/api/users/" + id)
            .header("Authorization", "Bearer admin-token"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").exists())
        .andExpect(jsonPath("$.email").value("user7@example.com"));
  }

  private Jwt jwt(String tokenValue, String sub, String email, String publicUserId) {
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
            "yomu_user_id", publicUserId,
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));
  }

  private UserProfile userProfile(
      String publicUserId,
      String supabaseUserId,
      String email,
      String role) {
    UserProfile user = new UserProfile();
    user.setId(UUID.fromString(publicUserId));
    user.setSupabaseUserId(supabaseUserId);
    user.setEmail(email);
    user.setUsername(email);
    user.setDisplayName(role + " User");
    user.setRole(role);
    user.setActive(true);
    return user;
  }
}

