package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class AuthLoginServiceTest {

  @Mock
  private SupabaseAuthClient supabaseAuthClient;

  @Mock
  private UserProfileService userProfileService;

  private AuthLoginService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new AuthLoginService(supabaseAuthClient, userProfileService);
  }

  @Test
  void loginRejectsInactiveAccountByEmailBeforeCallingIdentityProvider() {
    UserProfile inactive = new UserProfile();
    inactive.setEmail("inactive@example.com");
    inactive.setActive(false);
    when(userProfileService.findByEmail("inactive@example.com")).thenReturn(Optional.of(inactive));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.login("inactive@example.com", "password123"));

    assertEquals("Account is inactive", ex.getMessage());
    verify(supabaseAuthClient, never()).loginWithPassword("inactive@example.com", "password123");
  }

  @Test
  void loginRejectsInactiveAccountByUsernameBeforeCallingIdentityProvider() {
    UserProfile inactive = new UserProfile();
    inactive.setUsername("inactive-user");
    inactive.setEmail("inactive@example.com");
    inactive.setActive(false);
    when(userProfileService.findByUsername("inactive-user")).thenReturn(Optional.of(inactive));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.login("inactive-user", "password123"));

    assertEquals("Account is inactive", ex.getMessage());
    verify(supabaseAuthClient, never()).loginWithPassword("inactive@example.com", "password123");
  }
}
