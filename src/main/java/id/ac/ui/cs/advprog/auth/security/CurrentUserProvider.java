package id.ac.ui.cs.advprog.auth.security;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.Role;
import java.util.Collection;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class CurrentUserProvider {

  private static final String NO_AUTHENTICATED_USER_MESSAGE =
      "No authenticated user in security context";
  private static final String MISSING_PUBLIC_USER_ID_MESSAGE =
      "Missing public user id claim";

  public Optional<Jwt> getCurrentJwt() {
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

  public Optional<AuthenticatedUserPrincipal> getCurrentUser() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null) {
      return Optional.empty();
    }

    Object principal = authentication.getPrincipal();
    if (principal instanceof AuthenticatedUserPrincipal authenticatedUserPrincipal) {
      return Optional.of(authenticatedUserPrincipal);
    }
    Optional<Jwt> currentJwt = getCurrentJwt();
    if (currentJwt.isPresent()) {
      Jwt jwt = currentJwt.get();
      String publicUserId = resolvePublicUserId(jwt);
      if (!StringUtils.hasText(publicUserId)) {
        return Optional.empty();
      }
      return Optional.of(new AuthenticatedUserPrincipal(
          jwt.getSubject(),
          jwt.getClaimAsString("email"),
          resolveRole(authentication.getAuthorities(), jwt.getClaimAsString("role")),
          publicUserId));
    }

    return Optional.empty();
  }

  public AuthenticatedUserPrincipal requireCurrentUser() {
    return getCurrentUser().orElseThrow(
        () -> new UnauthorizedException(NO_AUTHENTICATED_USER_MESSAGE));
  }

  public String requireCurrentPublicUserId() {
    return getCurrentUser()
        .map(AuthenticatedUserPrincipal::publicUserId)
        .filter(StringUtils::hasText)
        .orElseThrow(() -> new UnauthorizedException(MISSING_PUBLIC_USER_ID_MESSAGE));
  }

  private String resolveRole(
      Collection<? extends GrantedAuthority> authorities,
      String claimedRole) {
    for (GrantedAuthority authority : authorities) {
      String authorityValue = authority.getAuthority();
      if (StringUtils.hasText(authorityValue) && authorityValue.startsWith("ROLE_")) {
        return Role.canonicalize(authorityValue.substring("ROLE_".length()));
      }
    }

    return Role.canonicalize(claimedRole);
  }

  private String resolvePublicUserId(Jwt jwt) {
    return jwt.getClaimAsString("yomu_user_id");
  }
}

