package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.security.AuthenticatedUserPrincipal;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class AdminControllerTest {

  @Mock
  private CurrentUserProvider currentUserProvider;

  @Mock
  private UserProfileService userProfileService;

  @InjectMocks
  private AdminController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void pingReturnsAdminAccessGrantedWhenProfileExists() {
    AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-admin-1", "admin@example.com", "ADMIN");
    UserProfile profile = new UserProfile();
    UUID userId = UUID.randomUUID();
    profile.setId(userId);

    when(currentUserProvider.requireCurrentUser()).thenReturn(principal);
    when(userProfileService.findBySupabaseUserId("sub-admin-1")).thenReturn(Optional.of(profile));

    var response = controller.ping();

    assertEquals(200, response.getStatusCodeValue());
    assertEquals("Admin access granted", response.getBody().message());
    assertEquals(userId, response.getBody().userId());
  }

  @Test
  void pingWithoutCurrentUserThrowsUnauthorizedException() {
    when(currentUserProvider.requireCurrentUser())
        .thenThrow(new UnauthorizedException("No authenticated user in security context"));

    UnauthorizedException ex = assertThrows(UnauthorizedException.class, () -> controller.ping());

    assertEquals("No authenticated user in security context", ex.getMessage());
  }

  @Test
  void pingWithoutProfileThrowsUnauthorizedException() {
    AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal("sub-admin-1", "admin@example.com", "ADMIN");

    when(currentUserProvider.requireCurrentUser()).thenReturn(principal);
    when(userProfileService.findBySupabaseUserId("sub-admin-1")).thenReturn(Optional.empty());

    UnauthorizedException ex = assertThrows(UnauthorizedException.class, () -> controller.ping());

    assertEquals("Authenticated user profile not found", ex.getMessage());
  }
}
