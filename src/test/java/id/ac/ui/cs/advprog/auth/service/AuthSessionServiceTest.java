package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class AuthSessionServiceTest {

  @Mock
  private SupabaseAuthClient supabaseAuthClient;

  @Mock
  private SupabaseJwtService supabaseJwtService;

  @Mock
  private TokenRevocationService tokenRevocationService;

  @Mock
  private UserProfileService userProfileService;

  private AuthSessionService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new AuthSessionService(
        supabaseAuthClient,
        supabaseJwtService,
        tokenRevocationService,
        userProfileService);
  }

  @Test
  void changePasswordUpdatesWhenCurrentPasswordIsValid() {
    when(supabaseAuthClient.loginWithPassword("user@example.com", "current-password"))
        .thenReturn(new SupabaseAuthClient.LoginResult(
            "access-token",
            "refresh-token",
            3600L,
            "sub-123",
            "user@example.com",
            "USER"));

    service.changePassword(
        "access-token",
        "user@example.com",
        "current-password",
        "new-password");

    verify(supabaseAuthClient).updatePassword("access-token", "new-password");
  }

  @Test
  void changePasswordRejectsWhenCurrentPasswordIsWrong() {
    when(supabaseAuthClient.loginWithPassword("user@example.com", "wrong-password"))
        .thenThrow(new UnauthorizedException("Invalid login credentials"));

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.changePassword(
            "access-token",
            "user@example.com",
            "wrong-password",
            "new-password"));

    assertEquals("Invalid login credentials", ex.getMessage());
    verify(supabaseAuthClient, never()).updatePassword("access-token", "new-password");
  }
}
