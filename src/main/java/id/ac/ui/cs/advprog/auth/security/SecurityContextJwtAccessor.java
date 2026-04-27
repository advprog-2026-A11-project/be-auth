package id.ac.ui.cs.advprog.auth.security;

import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

public final class SecurityContextJwtAccessor {

  private SecurityContextJwtAccessor() {
  }

  public static Optional<Jwt> getCurrentJwt() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null) {
      return Optional.empty();
    }

    if (authentication.getPrincipal() instanceof Jwt jwt) {
      return Optional.of(jwt);
    }

    if (authentication.getCredentials() instanceof Jwt jwt) {
      return Optional.of(jwt);
    }

    return Optional.empty();
  }
}
