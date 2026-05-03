package id.ac.ui.cs.advprog.auth.service.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import java.util.Optional;
import java.util.UUID;
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

    assertEquals(
        "Your account has been deactivated. Please contact an administrator.",
        ex.getMessage());
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

    assertEquals(
        "Your account has been deactivated. Please contact an administrator.",
        ex.getMessage());
    verify(supabaseAuthClient, never()).loginWithPassword("inactive@example.com", "password123");
  }

  @Test
  void loginResolvesPhoneIdentifierToEmailBeforeCallingIdentityProvider() {
    UserProfile user = new UserProfile();
    user.setId(UUID.randomUUID());
    user.setPhone("+628123456789");
    user.setEmail("phone@example.com");
    user.setRole("STUDENT");
    user.setActive(true);
    when(userProfileService.findByUsername("+628123456789")).thenReturn(Optional.empty());
    when(userProfileService.findByPhone("+628123456789")).thenReturn(Optional.of(user));
    when(userProfileService.findByEmail("phone@example.com")).thenReturn(Optional.of(user));
    when(supabaseAuthClient.loginWithPassword("phone@example.com", "password123"))
        .thenReturn(new SupabaseAuthClient.LoginResult(
            "access-token",
            "refresh-token",
            3600L,
            "supabase-user-phone",
            "phone@example.com",
            "STUDENT"));
    when(userProfileService.upsertFromIdentity(
        "supabase-user-phone",
        "phone@example.com",
        "STUDENT")).thenReturn(user);

    service.login("+628123456789", "password123");

    verify(supabaseAuthClient).loginWithPassword("phone@example.com", "password123");
  }

  @Test
  void loginRejectsInactiveAccountByPhoneBeforeCallingIdentityProvider() {
    UserProfile inactive = new UserProfile();
    inactive.setPhone("+628999999999");
    inactive.setEmail("inactive-phone@example.com");
    inactive.setActive(false);
    when(userProfileService.findByUsername("+628999999999")).thenReturn(Optional.empty());
    when(userProfileService.findByPhone("+628999999999")).thenReturn(Optional.of(inactive));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.login("+628999999999", "password123"));

    assertEquals(
        "Your account has been deactivated. Please contact an administrator.",
        ex.getMessage());
    verify(supabaseAuthClient, never())
        .loginWithPassword("inactive-phone@example.com", "password123");
  }
}


