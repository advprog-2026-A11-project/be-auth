package id.ac.ui.cs.advprog.auth.service.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.Optional;
import java.util.UUID;
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
  void findCurrentUserOrThrowUsesPublicUserId() {
    UserProfile profile = new UserProfile();
    profile.setId(UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11"));
    when(repository.findById(profile.getId())).thenReturn(Optional.of(profile));

    UserProfile resolved = service.findCurrentUserOrThrow(profile.getId().toString());

    assertEquals(profile, resolved);
    verify(repository).findById(profile.getId());
  }

  @Test
  void findCurrentUserOrThrowRejectsMissingIdentity() {
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> service.findCurrentUserOrThrow(" "));

    assertEquals("Authenticated public user id is required", ex.getMessage());
  }

  @Test
  void findCurrentUserOrThrowRejectsInvalidPublicUserId() {
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> service.findCurrentUserOrThrow("not-a-uuid"));

    assertEquals("Authenticated public user id is invalid", ex.getMessage());
  }

  @Test
  void findCurrentUserOrThrowRejectsMissingProfile() {
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> service.findCurrentUserOrThrow("c1f84e7b-bb84-412d-81bb-4449df141f11"));

    assertEquals("User profile not found", ex.getMessage());
  }
}


