package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class RoleMapperTest {

  @Test
  void canonicalizeMapsUserFamilyToStudent() {
    assertEquals("STUDENT", RoleMapper.canonicalize(null));
    assertEquals("STUDENT", RoleMapper.canonicalize(" "));
    assertEquals("STUDENT", RoleMapper.canonicalize("user"));
    assertEquals("STUDENT", RoleMapper.canonicalize("authenticated"));
    assertEquals("STUDENT", RoleMapper.canonicalize("student"));
  }

  @Test
  void canonicalizeKeepsAdminRole() {
    assertEquals("ADMIN", RoleMapper.canonicalize("admin"));
  }
}
