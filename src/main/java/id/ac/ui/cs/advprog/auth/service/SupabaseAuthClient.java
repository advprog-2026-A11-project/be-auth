package id.ac.ui.cs.advprog.auth.service;

public interface SupabaseAuthClient {

  LoginResult loginWithPassword(String email, String password);

  record LoginResult(
      String accessToken,
      String refreshToken,
      Long expiresIn,
      String supabaseUserId,
      String email,
      String role) {
  }
}
