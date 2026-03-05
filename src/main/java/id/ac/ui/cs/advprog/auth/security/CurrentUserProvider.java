package id.ac.ui.cs.advprog.auth.security;

import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class CurrentUserProvider {

  public Optional<AuthenticatedUserPrincipal> getCurrentUser() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      return Optional.empty();
    }

    Object principal = authentication.getPrincipal();
    if (principal instanceof AuthenticatedUserPrincipal authenticatedUserPrincipal) {
      return Optional.of(authenticatedUserPrincipal);
    }

    return Optional.empty();
  }

  public String requireCurrentUserId() {
    return getCurrentUser()
        .map(AuthenticatedUserPrincipal::sub)
        .orElseThrow(() -> new IllegalStateException("No authenticated user in security context"));
  }
}
