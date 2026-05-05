package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.security.AuthenticatedUserPrincipal;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class AdminControllerTest {

  @Mock
  private CurrentUserProvider currentUserProvider;

  @InjectMocks
  private AdminController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void pingReturnsAdminAccessGrantedWhenProfileExists() {
    AuthenticatedUserPrincipal principal =
        new AuthenticatedUserPrincipal(
            "sub-admin-1",
            "admin@example.com",
            "ADMIN",
            "c1f84e7b-bb84-412d-81bb-4449df141f11");

    when(currentUserProvider.requireCurrentUser()).thenReturn(principal);

    var response = controller.ping();

    assertEquals(200, response.getStatusCodeValue());
    assertEquals("Admin access granted", response.getBody().message());
    assertEquals(UUID.fromString("c1f84e7b-bb84-412d-81bb-4449df141f11"), response.getBody().userId());
  }

  @Test
  void pingWithoutCurrentUserThrowsUnauthorizedException() {
    when(currentUserProvider.requireCurrentUser())
        .thenThrow(new UnauthorizedException("Missing public user id claim"));

    UnauthorizedException ex = assertThrows(UnauthorizedException.class, () -> controller.ping());

    assertEquals("Missing public user id claim", ex.getMessage());
  }
}

