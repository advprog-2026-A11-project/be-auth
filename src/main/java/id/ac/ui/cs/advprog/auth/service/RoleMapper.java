package id.ac.ui.cs.advprog.auth.service;

import org.springframework.util.StringUtils;

public final class RoleMapper {

  private RoleMapper() {
  }

  public static String canonicalize(String incomingRole) {
    if (!StringUtils.hasText(incomingRole)) {
      return "STUDENT";
    }

    String normalized = incomingRole.trim().toUpperCase();
    if ("ADMIN".equals(normalized)) {
      return "ADMIN";
    }
    if ("USER".equals(normalized)
        || "AUTHENTICATED".equals(normalized)
        || "STUDENT".equals(normalized)) {
      return "STUDENT";
    }
    return "STUDENT";
  }
}
