package id.ac.ui.cs.advprog.auth.service.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class UserProfileIdentitySyncServiceTest {

  @Mock
  private UserProfileRepository repository;

  @Mock
  private SupabaseAuthClient supabaseAuthClient;

  private UserProfileIdentitySyncService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new UserProfileIdentitySyncService(repository, supabaseAuthClient);
  }

  @Test
  void upsertFromIdentityCreatesEnrichedProfile() {
    when(repository.findBySupabaseUserId("google-sub-123")).thenReturn(Optional.empty());
    when(repository.findByEmail("google@example.com")).thenReturn(Optional.empty());
    when(repository.existsByUsername("google")).thenReturn(false);
    when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    UserProfile created = service.upsertFromIdentity(
        "google-sub-123",
        "google@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub-123",
        "Google User");

    assertEquals("GOOGLE", created.getAuthProvider());
    assertEquals("google-sub-123", created.getGoogleSub());
    assertEquals("Google User", created.getDisplayName());
    assertEquals("STUDENT", created.getRole());
  }

  @Test
  void upsertFromIdentityRejectsConflictingSupabaseIdentityOnEmail() {
    UserProfile existing = new UserProfile();
    existing.setSupabaseUserId("existing-sub");
    when(repository.findBySupabaseUserId("new-sub")).thenReturn(Optional.empty());
    when(repository.findByEmail("user@example.com")).thenReturn(Optional.of(existing));

    ConflictException ex = assertThrows(
        ConflictException.class,
        () -> service.upsertFromIdentity(
            "new-sub",
            "user@example.com",
            "authenticated",
            "GOOGLE",
            "new-sub",
            "Google User"));

    assertEquals("Identity conflict for email", ex.getMessage());
  }

  @Test
  void syncAdminUpdateUsesSupabaseIdentityAsEmailSourceOfTruth() {
    UUID id = UUID.randomUUID();
    UserProfile existing = new UserProfile();
    existing.setId(id);
    existing.setSupabaseUserId("sub-123");
    existing.setEmail("old@example.com");
    existing.setUsername("old-user");
    existing.setDisplayName("Old Name");
    existing.setRole("STUDENT");
    existing.setActive(true);

    when(supabaseAuthClient.getUserById("sub-123")).thenReturn(new SupabaseAuthClient.IdentityUser(
        "sub-123",
        "provider@example.com",
        "authenticated",
        "password",
        null,
        "Provider Name"));

    UserProfile synced = service.syncAdminUpdate(existing, new UserProfile());

    assertEquals("provider@example.com", synced.getEmail());
    assertEquals("sub-123", synced.getSupabaseUserId());
  }

  @Test
  void syncAdminUpdateFallsBackToLocalEmailWhenSupabaseIdMissing() {
    UserProfile existing = new UserProfile();
    existing.setEmail("old@example.com");
    UserProfile incoming = new UserProfile();
    incoming.setEmail("new@example.com");
    when(repository.existsByEmail("new@example.com")).thenReturn(false);

    UserProfile synced = service.syncAdminUpdate(existing, incoming);

    assertEquals("new@example.com", synced.getEmail());
  }

  @Test
  void syncAdminUpdateUsesExistingSupabaseUserIdWhenIncomingIsBlank() {
    UserProfile existing = new UserProfile();
    existing.setSupabaseUserId("sub-123");
    when(supabaseAuthClient.getUserById("sub-123")).thenReturn(new SupabaseAuthClient.IdentityUser(
        "sub-123",
        "provider@example.com",
        "authenticated",
        "password",
        null,
        "Provider Name"));
    UserProfile incoming = new UserProfile();
    incoming.setSupabaseUserId(" ");

    UserProfile synced = service.syncAdminUpdate(existing, incoming);

    assertEquals("sub-123", synced.getSupabaseUserId());
    assertEquals("provider@example.com", synced.getEmail());
  }

  @Test
  void syncAdminUpdateKeepsGeneratedFallbackEmailWhenIdentityEmailMissing() {
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.empty());
    when(repository.findByEmail("sub-123@local.test")).thenReturn(Optional.empty());
    when(repository.existsByUsername("sub-123")).thenReturn(false);
    when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    UserProfile created = service.upsertFromIdentity(
        "sub-123",
        null,
        "authenticated",
        "PASSWORD",
        null,
        null);

    assertEquals("sub-123@local.test", created.getEmail());
    assertFalse(created.getUsername().isBlank());
  }

  @Test
  void upsertFromIdentityMergesPasswordAndGoogleProvidersOnExistingProfile() {
    UserProfile existing = new UserProfile();
    existing.setSupabaseUserId("sub-123");
    existing.setEmail("user@example.com");
    existing.setAuthProvider("PASSWORD");
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.of(existing));
    when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    UserProfile updated = service.upsertFromIdentity(
        "sub-123",
        "user@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub-123",
        "Google User");

    assertEquals("GOOGLE_PASSWORD", updated.getAuthProvider());
    assertEquals("google-sub-123", updated.getGoogleSub());
  }
}


