package id.ac.ui.cs.advprog.auth.security;

import id.ac.ui.cs.advprog.auth.service.RoleMapper;
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

  public Optional<AuthenticatedUserPrincipal> getCurrentUser() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null) {
      return Optional.empty();
    }

    Object principal = authentication.getPrincipal();
    if (principal instanceof AuthenticatedUserPrincipal authenticatedUserPrincipal) {
      return Optional.of(authenticatedUserPrincipal);
    }
    if (principal instanceof Jwt jwt) {
      return Optional.of(new AuthenticatedUserPrincipal(
          jwt.getSubject(),
          jwt.getClaimAsString("email"),
          resolveRole(authentication.getAuthorities(), jwt.getClaimAsString("role"))));
    }

    return Optional.empty();
  }

  private String resolveRole(
      Collection<? extends GrantedAuthority> authorities,
      String claimedRole) {
    for (GrantedAuthority authority : authorities) {
      String authorityValue = authority.getAuthority();
      if (StringUtils.hasText(authorityValue) && authorityValue.startsWith("ROLE_")) {
        return RoleMapper.canonicalize(authorityValue.substring("ROLE_".length()));
      }
    }

    return RoleMapper.canonicalize(claimedRole);
  }
}
