package id.ac.ui.cs.advprog.auth.model;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class UserProfileTest {

  @Test
  void gettersAndSettersWork() {
    UserProfile u = new UserProfile("user", "e@mail", "disp", "ADMIN", false);
    assertEquals("user", u.getUsername());
    assertEquals("e@mail", u.getEmail());
    assertEquals("disp", u.getDisplayName());
    assertEquals("ADMIN", u.getRole());
    assertFalse(u.isActive());
    u.setActive(true);
    assertTrue(u.isActive());
  }
}
