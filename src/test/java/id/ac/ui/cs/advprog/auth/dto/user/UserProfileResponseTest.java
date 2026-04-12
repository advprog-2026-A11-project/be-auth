package id.ac.ui.cs.advprog.auth.dto.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;

class UserProfileResponseTest {

  @Test
  void fromMapsEntityFields() {
    UserProfile user = new UserProfile();
    LocalDateTime createdAt = LocalDateTime.now().minusDays(1);
    LocalDateTime updatedAt = LocalDateTime.now();

    user.setId(10L);
    user.setUsername("demo");
    user.setEmail("demo@example.com");
    user.setSupabaseUserId("sub-xyz");
    user.setDisplayName("Demo User");
    user.setRole("USER");
    user.setActive(false);
    user.setCreatedAt(createdAt);
    user.setUpdatedAt(updatedAt);

    UserProfileResponse response = UserProfileResponse.from(user);

    assertEquals(10L, response.id());
    assertEquals("demo", response.username());
    assertEquals("demo@example.com", response.email());
    assertEquals("sub-xyz", response.supabaseUserId());
    assertEquals("Demo User", response.displayName());
    assertEquals("STUDENT", response.role());
    assertFalse(response.isActive());
    assertEquals(createdAt, response.createdAt());
    assertEquals(updatedAt, response.updatedAt());
  }
}
