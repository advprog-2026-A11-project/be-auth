package id.ac.ui.cs.advprog.auth.service;

public interface SupabaseAuthClient {

  IdentityUser getUserById(String supabaseUserId);

  LoginResult loginWithPassword(String email, String password);

  LoginResult refreshSession(String refreshToken);

  void logout(String accessToken);

  void updateEmail(String accessToken, String newEmail);

  void updatePassword(String accessToken, String newPassword);

  LoginResult registerWithPassword(
      String email,
      String password,
      String username,
      String displayName);

  record LoginResult(
      String accessToken,
      String refreshToken,
      Long expiresIn,
      String supabaseUserId,
      String email,
      String role) {
  }

  record IdentityUser(
      String supabaseUserId,
      String email,
      String role,
      String authProvider,
      String googleSub,
      String displayName) {
  }
}
