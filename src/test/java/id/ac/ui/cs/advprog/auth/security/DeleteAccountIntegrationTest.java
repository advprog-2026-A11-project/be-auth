package id.ac.ui.cs.advprog.auth.security;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
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
class DeleteAccountIntegrationTest {

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
  void deleteAccountSuccessAndTokenCannotBeUsedAfterward() throws Exception {
    UserProfile me = new UserProfile();
    me.setSupabaseUserId("sub-delete-1");
    me.setEmail("delete1@example.com");
    me.setUsername("delete1");
    me.setDisplayName("Delete One");
    me.setRole("USER");
    me.setActive(true);
    userProfileRepository.save(me);

    when(supabaseJwtService.validateAccessToken("token-delete-1"))
        .thenReturn(jwt("token-delete-1", "sub-delete-1", "delete1@example.com"));

    mockMvc.perform(delete("/api/users/me")
            .header("Authorization", "Bearer token-delete-1")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"confirmation\":\"DELETE\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Account deleted"))
        .andExpect(jsonPath("$.userId").value("sub-delete-1"));

    UserProfile persisted = userProfileRepository
        .findBySupabaseUserId("sub-delete-1")
        .orElseThrow();
    org.junit.jupiter.api.Assertions.assertFalse(persisted.isActive());

    mockMvc.perform(patch("/api/users/me")
            .header("Authorization", "Bearer token-delete-1")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"displayName\":\"Should Fail\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Account is inactive"));
  }

  @Test
  void deleteAccountInvalidConfirmationReturnsBadRequest() throws Exception {
    UserProfile me = new UserProfile();
    me.setSupabaseUserId("sub-delete-2");
    me.setEmail("delete2@example.com");
    me.setUsername("delete2");
    me.setDisplayName("Delete Two");
    me.setRole("USER");
    me.setActive(true);
    userProfileRepository.save(me);

    when(supabaseJwtService.validateAccessToken("token-delete-2"))
        .thenReturn(jwt("token-delete-2", "sub-delete-2", "delete2@example.com"));

    mockMvc.perform(delete("/api/users/me")
            .header("Authorization", "Bearer token-delete-2")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"confirmation\":\"NOPE\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value("confirmation must be DELETE"));
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
