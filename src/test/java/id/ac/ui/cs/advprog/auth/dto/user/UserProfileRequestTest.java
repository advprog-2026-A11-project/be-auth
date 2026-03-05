package id.ac.ui.cs.advprog.auth.dto.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class UserProfileRequestTest {

  @Test
  void gettersAndSettersWork() {
    UserProfileRequest request = new UserProfileRequest();
    request.setUsername("user");
    request.setEmail("user@example.com");
    request.setSupabaseUserId("sub-123");
    request.setDisplayName("User One");
    request.setRole("ADMIN");
    request.setActive(false);

    assertEquals("user", request.getUsername());
    assertEquals("user@example.com", request.getEmail());
    assertEquals("sub-123", request.getSupabaseUserId());
    assertEquals("User One", request.getDisplayName());
    assertEquals("ADMIN", request.getRole());
    assertFalse(request.getActive());
  }
}
