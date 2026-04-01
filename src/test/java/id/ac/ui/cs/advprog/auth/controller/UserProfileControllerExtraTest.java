package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.dto.user.DeleteAccountRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UpdateProfileRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserProfileRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserProfileResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.security.AuthenticatedUserPrincipal;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

class UserProfileControllerExtraTest {

  @Mock
  private UserProfileService service;

  @Mock
  private CurrentUserProvider currentUserProvider;

  @InjectMocks
  private UserProfileController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void allReturnsList() {
    UserProfile u1 = new UserProfile();
    u1.setUsername("u1");
    u1.setEmail("u1@example.com");
    UserProfile u2 = new UserProfile();
    u2.setUsername("u2");
    u2.setEmail("u2@example.com");
    when(service.findAll()).thenReturn(List.of(u1, u2));
    var list = controller.all();
    assertEquals(2, list.size());
    assertEquals("u1", list.get(0).username());
    assertEquals("u2@example.com", list.get(1).email());
  }

  @Test
  void getByIdNotFound() {
    when(service.findById(123L)).thenReturn(Optional.empty());
    ResponseEntity<UserProfileResponse> resp = controller.getById(123L);
    assertEquals(404, resp.getStatusCodeValue());
  }

  @Test
  void getByIdFound() {
    UserProfile u = new UserProfile();
    when(service.findById(5L)).thenReturn(Optional.of(u));
    ResponseEntity<UserProfileResponse> resp = controller.getById(5L);
    assertEquals(200, resp.getStatusCodeValue());
  }

  @Test
  void updateNotFoundReturnsNotFound() {
    when(service.update(eq(10L), any())).thenReturn(Optional.empty());
    ResponseEntity<UserProfileResponse> resp = controller.update(10L, new UserProfileRequest());
    assertEquals(404, resp.getStatusCodeValue());
  }

  @Test
  void normalizeIntegrationDefaultsSetsDefaults() {
    UserProfileRequest request = new UserProfileRequest();
    request.setUsername(null);
    request.setDisplayName(null);
    request.setRole("");
    request.setEmail("");
    // call create to trigger normalizeIntegrationDefaults
    when(service.create(any())).thenAnswer(i -> i.getArgument(0));
    var resp = controller.create(request);
    assertEquals(201, resp.getStatusCodeValue());
    UserProfileResponse created = resp.getBody();
    assertNotNull(created.username());
    assertNotNull(created.displayName());
    assertEquals("USER", created.role());
    assertTrue(created.email().endsWith("@local.test"));
  }

  @Test
  void updateMeSuccess() {
    final UpdateProfileRequest request = new UpdateProfileRequest("new-user", "New User");
    final AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-123", "user@example.com", "USER");

    UserProfile updated = new UserProfile();
    updated.setSupabaseUserId("sub-123");
    updated.setUsername("new-user");
    updated.setDisplayName("New User");
    updated.setEmail("user@example.com");

    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.of(principal));
    when(service.updateCurrentUserProfile("sub-123", "user@example.com", "new-user", "New User"))
        .thenReturn(updated);

    var response = controller.updateMe(request);
    assertEquals(200, response.getStatusCodeValue());
    assertEquals("Profile updated", response.getBody().get("message"));
    assertEquals("sub-123", response.getBody().get("userId"));
  }

  @Test
  void updateMeWithUsernameOnlySuccess() {
    final UpdateProfileRequest request = new UpdateProfileRequest("new-user", " ");
    final AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-123", "user@example.com", "USER");

    UserProfile updated = new UserProfile();
    updated.setSupabaseUserId("sub-123");
    updated.setUsername("new-user");
    updated.setDisplayName("Current Name");
    updated.setEmail("user@example.com");

    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.of(principal));
    when(service.updateCurrentUserProfile("sub-123", "user@example.com", "new-user", " "))
        .thenReturn(updated);

    var response = controller.updateMe(request);
    assertEquals(200, response.getStatusCodeValue());
    assertEquals("new-user", response.getBody().get("username"));
  }

  @Test
  void updateMeWithDisplayNameOnlySuccess() {
    final UpdateProfileRequest request = new UpdateProfileRequest(" ", "New User");
    final AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-123", "user@example.com", "USER");

    UserProfile updated = new UserProfile();
    updated.setSupabaseUserId("sub-123");
    updated.setUsername("current-user");
    updated.setDisplayName("New User");
    updated.setEmail("user@example.com");

    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.of(principal));
    when(service.updateCurrentUserProfile("sub-123", "user@example.com", " ", "New User"))
        .thenReturn(updated);

    var response = controller.updateMe(request);
    assertEquals(200, response.getStatusCodeValue());
    assertEquals("New User", response.getBody().get("displayName"));
  }

  @Test
  void updateMeWithNullDisplayNameSuccess() {
    final UpdateProfileRequest request = new UpdateProfileRequest("new-user", null);
    final AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-123", "user@example.com", "USER");

    UserProfile updated = new UserProfile();
    updated.setSupabaseUserId("sub-123");
    updated.setUsername("new-user");
    updated.setDisplayName("Current Name");
    updated.setEmail("user@example.com");

    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.of(principal));
    when(service.updateCurrentUserProfile("sub-123", "user@example.com", "new-user", null))
        .thenReturn(updated);

    var response = controller.updateMe(request);
    assertEquals(200, response.getStatusCodeValue());
    assertEquals("new-user", response.getBody().get("username"));
  }

  @Test
  void updateMeWithNullUsernameSuccess() {
    final UpdateProfileRequest request = new UpdateProfileRequest(null, "New User");
    final AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-123", "user@example.com", "USER");

    UserProfile updated = new UserProfile();
    updated.setSupabaseUserId("sub-123");
    updated.setUsername("current-user");
    updated.setDisplayName("New User");
    updated.setEmail("user@example.com");

    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.of(principal));
    when(service.updateCurrentUserProfile("sub-123", "user@example.com", null, "New User"))
        .thenReturn(updated);

    var response = controller.updateMe(request);
    assertEquals(200, response.getStatusCodeValue());
    assertEquals("New User", response.getBody().get("displayName"));
  }

  @Test
  void updateMeWithoutFieldsThrowsIllegalArgumentException() {
    UpdateProfileRequest request = new UpdateProfileRequest(" ", " ");
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> controller.updateMe(request));
    assertEquals("At least one field must be provided: username or displayName", ex.getMessage());
  }

  @Test
  void updateMeWithoutFieldsWhenNullThrowsIllegalArgumentException() {
    UpdateProfileRequest request = new UpdateProfileRequest(null, null);
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> controller.updateMe(request));
    assertEquals("At least one field must be provided: username or displayName", ex.getMessage());
  }

  @Test
  void updateMeWithoutCurrentUserThrowsIllegalStateException() {
    UpdateProfileRequest request = new UpdateProfileRequest("new-user", null);
    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.empty());

    IllegalStateException ex =
        assertThrows(IllegalStateException.class, () -> controller.updateMe(request));
    assertEquals("No authenticated user in security context", ex.getMessage());
  }

  @Test
  void deleteMeSuccess() {
    final DeleteAccountRequest request = new DeleteAccountRequest("DELETE");
    final AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-789", "user2@example.com", "USER");
    UserProfile deactivated = new UserProfile();
    deactivated.setSupabaseUserId("sub-789");

    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.of(principal));
    when(service.deactivateCurrentUser("sub-789", "user2@example.com")).thenReturn(deactivated);

    var response = controller.deleteMe(request);
    assertEquals(200, response.getStatusCodeValue());
    assertEquals("Account deleted", response.getBody().get("message"));
    assertEquals("sub-789", response.getBody().get("userId"));
  }

  @Test
  void deleteMeInvalidConfirmationThrowsIllegalArgumentException() {
    DeleteAccountRequest request = new DeleteAccountRequest("nope");
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> controller.deleteMe(request));
    assertEquals("confirmation must be DELETE", ex.getMessage());
  }

  @Test
  void deleteMeWithoutCurrentUserThrowsIllegalStateException() {
    DeleteAccountRequest request = new DeleteAccountRequest("DELETE");
    when(currentUserProvider.getCurrentUser()).thenReturn(Optional.empty());

    IllegalStateException ex =
        assertThrows(IllegalStateException.class, () -> controller.deleteMe(request));
    assertEquals("No authenticated user in security context", ex.getMessage());
  }
}
