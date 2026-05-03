package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.jwt.Jwt;

class GoogleSsoIdentityServiceTest {

  @Mock
  private UserProfileService userProfileService;

  @Mock
  private AuthSessionService authSessionService;

  private GoogleSsoIdentityService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new GoogleSsoIdentityService(userProfileService, authSessionService);
  }

  @Test
  void provisionIdentityRejectsMissingSubject() {
    Jwt jwt = jwtWithClaims(Map.of(
        "email", "google@example.com",
        "role", "authenticated"));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.provisionIdentity(jwt, "access-token"));

    assertEquals("SSO callback token missing subject", ex.getMessage());
  }

  @Test
  void provisionIdentityMarksExistingEmailAsLinked() {
    UserProfile existing = new UserProfile();
    existing.setId(UUID.randomUUID());
    existing.setEmail("google@example.com");
    when(userProfileService.findBySupabaseUserId("google-sub")).thenReturn(Optional.empty());
    when(userProfileService.findByEmail("google@example.com")).thenReturn(Optional.of(existing));
    when(userProfileService.upsertFromIdentity(
        "google-sub",
        "google@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub",
        "Metadata Name")).thenReturn(existing);

    GoogleSsoIdentityService.ProvisionedIdentity provisioned = service.provisionIdentity(
        jwtWithClaims(Map.of(
            "sub", "google-sub",
            "email", "google@example.com",
            "role", "authenticated",
            "user_metadata", Map.of("name", "Metadata Name"))),
        "access-token");

    assertTrue(provisioned.linked());
    assertEquals(existing, provisioned.profile());
    verify(authSessionService, never()).logout("access-token");
  }

  @Test
  void provisionIdentityLogsOutInactiveExistingEmailIdentity() {
    UserProfile inactive = new UserProfile();
    inactive.setEmail("inactive@example.com");
    inactive.setActive(false);
    when(userProfileService.findBySupabaseUserId("google-sub")).thenReturn(Optional.empty());
    when(userProfileService.findByEmail("inactive@example.com")).thenReturn(Optional.of(inactive));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.provisionIdentity(
            jwtWithClaims(Map.of(
                "sub", "google-sub",
                "email", "inactive@example.com",
                "role", "authenticated")),
            "access-token"));

    assertEquals(
        "Your account has been deactivated. Please contact an administrator.",
        ex.getMessage());
    verify(authSessionService).logout("access-token");
  }

  @Test
  void provisionIdentityFallsBackToJwtNameClaimWhenFullNameMissing() {
    UserProfile profile = new UserProfile();
    profile.setId(UUID.randomUUID());
    when(userProfileService.findBySupabaseUserId("google-sub")).thenReturn(Optional.empty());
    when(userProfileService.findByEmail("google@example.com")).thenReturn(Optional.empty());
    when(userProfileService.upsertFromIdentity(
        "google-sub",
        "google@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub",
        "Claim Name")).thenReturn(profile);

    GoogleSsoIdentityService.ProvisionedIdentity provisioned = service.provisionIdentity(
        jwtWithClaims(Map.of(
            "sub", "google-sub",
            "email", "google@example.com",
            "role", "authenticated",
            "name", "Claim Name")),
        "access-token");

    assertEquals(profile, provisioned.profile());
  }

  @Test
  void provisionIdentityFallsBackToBlankDisplayNameWhenMetadataMissing() {
    UserProfile profile = new UserProfile();
    profile.setId(UUID.randomUUID());
    when(userProfileService.findBySupabaseUserId("google-sub")).thenReturn(Optional.of(profile));
    when(userProfileService.upsertFromIdentity(
        "google-sub",
        "google@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub",
        "")).thenReturn(profile);

    GoogleSsoIdentityService.ProvisionedIdentity provisioned = service.provisionIdentity(
        jwtWithClaims(Map.of(
            "sub", "google-sub",
            "email", "google@example.com",
            "role", "authenticated")),
        "access-token");

    assertTrue(provisioned.linked());
    assertEquals(profile, provisioned.profile());
  }

  @Test
  void provisionIdentityReturnsUnlinkedWhenEmailMissingAndIdentityAbsent() {
    UserProfile profile = new UserProfile();
    profile.setId(UUID.randomUUID());
    when(userProfileService.findBySupabaseUserId("google-sub")).thenReturn(Optional.empty());
    when(userProfileService.upsertFromIdentity(
        "google-sub",
        null,
        "authenticated",
        "GOOGLE",
        "google-sub",
        "")).thenReturn(profile);

    GoogleSsoIdentityService.ProvisionedIdentity provisioned = service.provisionIdentity(
        jwtWithClaims(Map.of(
            "sub", "google-sub",
            "role", "authenticated")),
        "access-token");

    assertEquals(false, provisioned.linked());
    verify(userProfileService, never()).findByEmail(org.mockito.ArgumentMatchers.any());
  }

  @Test
  void provisionIdentityPrefersMetadataFullNameWhenClaimsMissing() {
    UserProfile profile = new UserProfile();
    profile.setId(UUID.randomUUID());
    when(userProfileService.findBySupabaseUserId("google-sub")).thenReturn(Optional.of(profile));
    when(userProfileService.upsertFromIdentity(
        "google-sub",
        "google@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub",
        "Metadata Full Name")).thenReturn(profile);

    GoogleSsoIdentityService.ProvisionedIdentity provisioned = service.provisionIdentity(
        jwtWithClaims(Map.of(
            "sub", "google-sub",
            "email", "google@example.com",
            "role", "authenticated",
            "user_metadata", Map.of("full_name", "Metadata Full Name"))),
        "access-token");

    assertTrue(provisioned.linked());
    assertEquals(profile, provisioned.profile());
  }

  @Test
  void provisionIdentityIgnoresBlankMetadataName() {
    UserProfile profile = new UserProfile();
    profile.setId(UUID.randomUUID());
    when(userProfileService.findBySupabaseUserId("google-sub")).thenReturn(Optional.of(profile));
    when(userProfileService.upsertFromIdentity(
        "google-sub",
        "google@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub",
        "")).thenReturn(profile);

    GoogleSsoIdentityService.ProvisionedIdentity provisioned = service.provisionIdentity(
        jwtWithClaims(Map.of(
            "sub", "google-sub",
            "email", "google@example.com",
            "role", "authenticated",
            "user_metadata", Map.of("name", "   "))),
        "access-token");

    assertTrue(provisioned.linked());
    assertEquals(profile, provisioned.profile());
  }

  @Test
  void provisionIdentityFallsBackWhenMetadataMapHasNoSupportedName() {
    UserProfile profile = new UserProfile();
    profile.setId(UUID.randomUUID());
    when(userProfileService.findBySupabaseUserId("google-sub")).thenReturn(Optional.of(profile));
    when(userProfileService.upsertFromIdentity(
        "google-sub",
        "google@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub",
        "")).thenReturn(profile);

    GoogleSsoIdentityService.ProvisionedIdentity provisioned = service.provisionIdentity(
        jwtWithClaims(Map.of(
            "sub", "google-sub",
            "email", "google@example.com",
            "role", "authenticated",
            "user_metadata", Map.of("locale", "id-ID"))),
        "access-token");

    assertTrue(provisioned.linked());
    assertEquals(profile, provisioned.profile());
  }

  private Jwt jwtWithClaims(Map<String, Object> claims) {
    return new Jwt(
        "access-token",
        Instant.now(),
        Instant.now().plusSeconds(3600),
        Map.of("alg", "none"),
        new java.util.HashMap<>(Map.of(
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1")) {{
              putAll(claims);
            }});
  }
}
