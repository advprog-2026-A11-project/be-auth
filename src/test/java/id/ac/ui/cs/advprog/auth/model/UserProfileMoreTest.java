package id.ac.ui.cs.advprog.auth.model;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;

class UserProfileMoreTest {

  @Test
  void createdAtAndUpdatedAtSetters() {
    UserProfile u = new UserProfile();
    LocalDateTime now = LocalDateTime.now();
    u.setCreatedAt(now);
    u.setUpdatedAt(now.plusHours(1));
    assertEquals(now, u.getCreatedAt());
    assertEquals(now.plusHours(1), u.getUpdatedAt());
  }

  @Test
  void passwordHashSetterWorks() {
    UserProfile u = new UserProfile();
    u.setPasswordHash("p");
    assertEquals("p", u.getPasswordHash());
  }
}
