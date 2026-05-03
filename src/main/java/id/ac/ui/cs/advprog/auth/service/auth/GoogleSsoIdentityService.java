package id.ac.ui.cs.advprog.auth.service.auth;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class GoogleSsoIdentityService {

  private static final String DEACTIVATED_ACCOUNT_MESSAGE =
      "Your account has been deactivated. Please contact an administrator.";

  private final UserProfileService userProfileService;
  private final AuthSessionService authSessionService;

  public GoogleSsoIdentityService(
      UserProfileService userProfileService,
      AuthSessionService authSessionService) {
    this.userProfileService = userProfileService;
    this.authSessionService = authSessionService;
  }

  public ProvisionedIdentity provisionIdentity(Jwt jwt, String accessToken) {
    String sub = jwt.getSubject();
    if (!StringUtils.hasText(sub)) {
      throw new UnauthorizedException("SSO callback token missing subject");
    }

    String email = jwt.getClaimAsString("email");
    ensureIdentityIsActive(accessToken, sub, email);

    boolean linked = isExistingIdentity(sub, email);
    UserProfile profile = userProfileService.upsertFromIdentity(
        sub,
        email,
        jwt.getClaimAsString("role"),
        "GOOGLE",
        sub,
        extractDisplayName(jwt));

    return new ProvisionedIdentity(profile, linked);
  }

  private boolean isExistingIdentity(String sub, String email) {
    Optional<UserProfile> bySub = userProfileService.findBySupabaseUserId(sub);
    if (bySub.isPresent()) {
      return true;
    }
    return StringUtils.hasText(email) && userProfileService.findByEmail(email).isPresent();
  }

  private void ensureIdentityIsActive(String accessToken, String sub, String email) {
    Optional<UserProfile> existing = userProfileService.findBySupabaseUserId(sub);
    if (existing.isEmpty() && StringUtils.hasText(email)) {
      existing = userProfileService.findByEmail(email);
    }

    if (existing.isPresent() && !existing.get().isActive()) {
      authSessionService.logout(accessToken);
      throw new UnauthorizedException(DEACTIVATED_ACCOUNT_MESSAGE);
    }
  }

  @SuppressWarnings("unchecked")
  private String extractDisplayName(Jwt jwt) {
    String fullName = jwt.getClaimAsString("full_name");
    if (StringUtils.hasText(fullName)) {
      return fullName.trim();
    }

    String name = jwt.getClaimAsString("name");
    if (StringUtils.hasText(name)) {
      return name.trim();
    }

    Object userMetadata = jwt.getClaims().get("user_metadata");
    if (userMetadata instanceof Map<?, ?> metadata) {
      Object metadataName = metadata.get("full_name");
      if (metadataName == null) {
        metadataName = metadata.get("name");
      }
      if (metadataName != null && StringUtils.hasText(String.valueOf(metadataName))) {
        return String.valueOf(metadataName).trim();
      }
    }

    return "";
  }

  public record ProvisionedIdentity(UserProfile profile, boolean linked) {
  }
}


