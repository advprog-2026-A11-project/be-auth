package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class CurrentUserProfileLookupServiceTest {

  @Mock
  private UserProfileRepository repository;

  private CurrentUserProfileLookupService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new CurrentUserProfileLookupService(repository);
  }

  @Test
  void findCurrentUserOrThrowPrefersSupabaseUserId() {
    UserProfile profile = new UserProfile();
    profile.setSupabaseUserId("sub-123");
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.of(profile));

    UserProfile resolved = service.findCurrentUserOrThrow("sub-123", "user@example.com");

    assertEquals(profile, resolved);
    verify(repository).findBySupabaseUserId("sub-123");
  }

  @Test
  void findCurrentUserOrThrowFallsBackToNormalizedEmail() {
    UserProfile profile = new UserProfile();
    profile.setEmail("user@example.com");
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.empty());
    when(repository.findByEmail("user@example.com")).thenReturn(Optional.of(profile));

    UserProfile resolved = service.findCurrentUserOrThrow("sub-123", " User@example.com ");

    assertEquals(profile, resolved);
    verify(repository).findByEmail("user@example.com");
  }

  @Test
  void findCurrentUserOrThrowRejectsMissingIdentity() {
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> service.findCurrentUserOrThrow(" ", " "));

    assertEquals("Authenticated user identity is required", ex.getMessage());
  }

  @Test
  void findCurrentUserOrThrowRejectsMissingProfile() {
    when(repository.findByEmail("user@example.com")).thenReturn(Optional.empty());

    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> service.findCurrentUserOrThrow(null, "user@example.com"));

    assertEquals("User profile not found", ex.getMessage());
  }
}
