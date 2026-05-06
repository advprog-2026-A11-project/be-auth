package id.ac.ui.cs.advprog.auth.model;

import org.springframework.util.StringUtils;

public enum Role {
  STUDENT,
  ADMIN;

  public static Role from(String incomingRole) {
    if (!StringUtils.hasText(incomingRole)) {
      return STUDENT;
    }

    String normalized = incomingRole.trim().toUpperCase();
    if ("ADMIN".equals(normalized)) {
      return ADMIN;
    }
    return STUDENT;
  }

  public static String canonicalize(String incomingRole) {
    return from(incomingRole).name();
  }
}

