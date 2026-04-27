package id.ac.ui.cs.advprog.auth.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class RoleTest {

  @Test
  void canonicalizeMapsUserFamilyToStudent() {
    assertEquals("STUDENT", Role.canonicalize(null));
    assertEquals("STUDENT", Role.canonicalize(" "));
    assertEquals("STUDENT", Role.canonicalize("user"));
    assertEquals("STUDENT", Role.canonicalize("authenticated"));
    assertEquals("STUDENT", Role.canonicalize("student"));
  }

  @Test
  void canonicalizeKeepsAdminRole() {
    assertEquals("ADMIN", Role.canonicalize("admin"));
  }
}
