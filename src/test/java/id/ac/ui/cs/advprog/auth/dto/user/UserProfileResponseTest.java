package id.ac.ui.cs.advprog.auth.dto.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.time.LocalDateTime;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UserProfileResponseTest {

  @Test
  void fromMapsEntityFields() {
    UserProfile user = new UserProfile();
    LocalDateTime createdAt = LocalDateTime.now().minusDays(1);
    LocalDateTime updatedAt = LocalDateTime.now();
    UUID id = UUID.randomUUID();

    user.setId(id);
    user.setUsername("demo");
    user.setEmail("demo@example.com");
    user.setSupabaseUserId("sub-xyz");
    user.setDisplayName("Demo User");
    user.setRole("USER");
    user.setActive(false);
    user.setCreatedAt(createdAt);
    user.setUpdatedAt(updatedAt);

    UserProfileResponse response = UserProfileResponse.from(user);

    assertEquals(id, response.id());
    assertEquals("demo", response.username());
    assertEquals("demo@example.com", response.email());
    assertEquals("Demo User", response.displayName());
    assertEquals("STUDENT", response.role());
    assertFalse(response.isActive());
    assertEquals(createdAt, response.createdAt());
    assertEquals(updatedAt, response.updatedAt());
  }
}
