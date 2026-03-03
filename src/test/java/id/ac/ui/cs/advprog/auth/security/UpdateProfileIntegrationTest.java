package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
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
class UpdateProfileIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private UserProfileRepository userProfileRepository;

  @MockBean
  private SupabaseJwtService supabaseJwtService;

  @BeforeEach
  void setUp() {
    userProfileRepository.deleteAll();
  }

  @Test
  void updateProfileSuccess() throws Exception {
    UserProfile me = new UserProfile();
    me.setSupabaseUserId("sub-user-1");
    me.setEmail("user1@example.com");
    me.setUsername("user1");
    me.setDisplayName("User One");
    me.setRole("USER");
    me.setActive(true);
    userProfileRepository.save(me);

    when(supabaseJwtService.validateAccessToken("token-user-1"))
        .thenReturn(jwt("token-user-1", "sub-user-1", "user1@example.com"));

    mockMvc.perform(patch("/api/users/me")
            .header("Authorization", "Bearer token-user-1")
            .contentType(MediaType.APPLICATION_JSON)
            .content("""
                {
                  "username": "user1-new",
                  "displayName": "User One New"
                }
                """))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Profile updated"))
        .andExpect(jsonPath("$.username").value("user1-new"))
        .andExpect(jsonPath("$.displayName").value("User One New"));
  }

  @Test
  void updateProfileUsernameConflictReturnsConflict() throws Exception {
    UserProfile me = new UserProfile();
    me.setSupabaseUserId("sub-user-2");
    me.setEmail("user2@example.com");
    me.setUsername("user2");
    me.setDisplayName("User Two");
    me.setRole("USER");
    me.setActive(true);
    userProfileRepository.save(me);

    UserProfile other = new UserProfile();
    other.setSupabaseUserId("sub-user-3");
    other.setEmail("user3@example.com");
    other.setUsername("taken-username");
    other.setDisplayName("User Three");
    other.setRole("USER");
    other.setActive(true);
    userProfileRepository.save(other);

    when(supabaseJwtService.validateAccessToken("token-user-2"))
        .thenReturn(jwt("token-user-2", "sub-user-2", "user2@example.com"));

    mockMvc.perform(patch("/api/users/me")
            .header("Authorization", "Bearer token-user-2")
            .contentType(MediaType.APPLICATION_JSON)
            .content("""
                {
                  "username": "taken-username"
                }
                """))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.message").value("Username already taken"));
  }

  @Test
  void updateProfileWithoutTokenReturnsUnauthorized() throws Exception {
    mockMvc.perform(patch("/api/users/me")
            .contentType(MediaType.APPLICATION_JSON)
            .content("""
                {
                  "username": "abc",
                  "displayName": "ABC"
                }
                """))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void updateOtherUserByIdWithUserRoleReturnsForbidden() throws Exception {
    UserProfile me = new UserProfile();
    me.setSupabaseUserId("sub-user-4");
    me.setEmail("user4@example.com");
    me.setUsername("user4");
    me.setDisplayName("User Four");
    me.setRole("USER");
    me.setActive(true);
    userProfileRepository.save(me);

    when(supabaseJwtService.validateAccessToken("token-user-4"))
        .thenReturn(jwt("token-user-4", "sub-user-4", "user4@example.com"));

    mockMvc.perform(put("/api/users/999")
            .header("Authorization", "Bearer token-user-4")
            .contentType(MediaType.APPLICATION_JSON)
            .content("""
                {
                  "username": "hacker",
                  "email": "hacker@example.com",
                  "displayName": "Hacker",
                  "role": "USER",
                  "active": true
                }
                """))
        .andExpect(status().isForbidden());
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
