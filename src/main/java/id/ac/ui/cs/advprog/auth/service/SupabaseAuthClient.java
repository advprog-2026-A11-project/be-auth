package id.ac.ui.cs.advprog.auth.service;

public interface SupabaseAuthClient {

  LoginResult loginWithPassword(String email, String password);

  LoginResult refreshSession(String refreshToken);

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
}
