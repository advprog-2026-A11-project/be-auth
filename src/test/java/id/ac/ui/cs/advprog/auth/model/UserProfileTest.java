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
    u.setPhone("+628123456789");
    u.setAuthProvider("PASSWORD");
    u.setGoogleSub("google-sub-1");
    u.setActive(true);
    assertEquals("+628123456789", u.getPhone());
    assertEquals("PASSWORD", u.getAuthProvider());
    assertEquals("google-sub-1", u.getGoogleSub());
    assertTrue(u.isActive());
  }
}

