package id.ac.ui.cs.advprog.auth.service.supabase;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HttpSupabaseAuthClientTest {

  private HttpServer server;
  private HttpSupabaseAuthClient client;
  private HttpSupabaseAuthClient clientWithoutServiceRoleKey;

  @BeforeEach
  void setUp() throws Exception {
    server = HttpServer.create(new InetSocketAddress(0), 0);
    server.createContext("/auth/v1/admin/users", new AdminUserHandler());
    server.createContext("/auth/v1/token", new TokenHandler());
    server.createContext("/auth/v1/signup", new SignupHandler());
    server.createContext("/auth/v1/logout", new LogoutHandler());
    server.createContext("/auth/v1/user", new UserUpdateHandler());
    server.start();

    String baseUrl = "http://localhost:" + server.getAddress().getPort();
    client = new HttpSupabaseAuthClient(baseUrl, "anon-key", "service-role-key");
    clientWithoutServiceRoleKey = new HttpSupabaseAuthClient(baseUrl, "anon-key", "");
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
  }

  @Test
  void getUserByIdParsesStructuredIdentityFields() {
    SupabaseAuthClient.IdentityUser user = client.getUserById("user-123");

    assertEquals("user-123", user.supabaseUserId());
    assertEquals("admin@example.com", user.email());
    assertEquals("admin", user.role());
    assertEquals("google", user.authProvider());
    assertEquals("google-sub-123", user.googleSub());
    assertEquals("Admin User", user.displayName());
  }

  @Test
  void getUserByIdRejectsEmptyResponseBody() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> client.getUserById("empty-user"));

    assertEquals("User lookup failed: empty response from identity provider", ex.getMessage());
  }

  @Test
  void getUserByIdRejectsInvalidIdentityPayload() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> client.getUserById("invalid-user"));

    assertEquals("User lookup failed: invalid identity payload", ex.getMessage());
  }

  @Test
  void getUserByIdMapsClientErrorToIllegalArgumentException() {
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> client.getUserById("missing-user"));

    assertEquals("User not found", ex.getMessage());
  }

  @Test
  void getUserByIdMapsServerErrorToIllegalStateException() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> client.getUserById("server-error-user"));

    assertEquals("Identity provider error while loading user", ex.getMessage());
  }

  @Test
  void loginWithPasswordParsesTokenAndUserPayload() {
    SupabaseAuthClient.LoginResult result =
        client.loginWithPassword("user@example.com", "password123");

    assertEquals("access-token", result.accessToken());
    assertEquals("refresh-token", result.refreshToken());
    assertEquals(3600L, result.expiresIn());
    assertEquals("user-456", result.supabaseUserId());
    assertEquals("user@example.com", result.email());
    assertEquals("student", result.role());
  }

  @Test
  void loginWithPasswordRejectsEmptyResponseBody() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.loginWithPassword("empty@example.com", "password123"));

    assertEquals("Login failed: empty response from identity provider", ex.getMessage());
  }

  @Test
  void loginWithPasswordRejectsMissingUserObject() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.loginWithPassword("missing-user@example.com", "password123"));

    assertEquals("Login failed: user information missing in response", ex.getMessage());
  }

  @Test
  void loginWithPasswordRejectsInvalidTokenPayload() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.loginWithPassword("invalid-token@example.com", "password123"));

    assertEquals("Login failed: invalid token payload from identity provider", ex.getMessage());
  }

  @Test
  void loginWithPasswordMapsServerErrorToIllegalStateException() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> client.loginWithPassword("server-error@example.com", "password123"));

    assertEquals("Identity provider error while login", ex.getMessage());
  }

  @Test
  void refreshSessionParsesTokenAndUserPayload() {
    SupabaseAuthClient.LoginResult result = client.refreshSession("refresh-token");

    assertEquals("refreshed-access-token", result.accessToken());
    assertEquals("refreshed-refresh-token", result.refreshToken());
    assertEquals(7200L, result.expiresIn());
    assertEquals("user-789", result.supabaseUserId());
    assertEquals("refresh@example.com", result.email());
    assertEquals("admin", result.role());
  }

  @Test
  void refreshSessionRejectsEmptyResponseBody() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.refreshSession("empty-refresh-token"));

    assertEquals("Refresh failed: empty response from identity provider", ex.getMessage());
  }

  @Test
  void refreshSessionRejectsMissingUserObject() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.refreshSession("missing-user-refresh-token"));

    assertEquals("Refresh failed: user information missing in response", ex.getMessage());
  }

  @Test
  void refreshSessionRejectsInvalidTokenPayload() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.refreshSession("invalid-refresh-token"));

    assertEquals("Refresh failed: invalid token payload from identity provider", ex.getMessage());
  }

  @Test
  void refreshSessionMapsClientErrorToUnauthorizedException() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.refreshSession("bad-refresh-token"));

    assertEquals("Refresh token invalid", ex.getMessage());
  }

  @Test
  void refreshSessionMapsServerErrorToIllegalStateException() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> client.refreshSession("server-error-refresh-token"));

    assertEquals("Identity provider error while refreshing session", ex.getMessage());
  }

  @Test
  void registerWithPasswordMapsAlreadyRegisteredToConflictException() {
    ConflictException ex = assertThrows(
        ConflictException.class,
        () -> client.registerWithPassword(
            "taken@example.com",
            "password123",
            "taken-user",
            "Taken User"));

    assertEquals("Email already registered", ex.getMessage());
  }

  @Test
  void registerWithPasswordWithoutServiceRoleReturnsParsedSignupPayload() {
    SupabaseAuthClient.LoginResult result = clientWithoutServiceRoleKey.registerWithPassword(
        "new@example.com",
        "password123",
        "new-user",
        "New User");

    assertEquals("signup-access-token", result.accessToken());
    assertEquals("signup-refresh-token", result.refreshToken());
    assertEquals("signup-user-1", result.supabaseUserId());
  }

  @Test
  void registerWithPasswordWithoutServiceRoleAllowsEmptyMetadata() {
    SupabaseAuthClient.LoginResult result = clientWithoutServiceRoleKey.registerWithPassword(
        "plain@example.com",
        "password123",
        " ",
        null);

    assertEquals("signup-user-plain", result.supabaseUserId());
  }

  @Test
  void registerWithPasswordWithoutServiceRoleRejectsEmptyResponseBody() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> clientWithoutServiceRoleKey.registerWithPassword(
            "empty-signup@example.com",
            "password123",
            "new-user",
            "New User"));

    assertEquals("Registration failed: empty response from identity provider", ex.getMessage());
  }

  @Test
  void registerWithPasswordWithoutServiceRoleRejectsMissingUserObject() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> clientWithoutServiceRoleKey.registerWithPassword(
            "missing-signup-user@example.com",
            "password123",
            "new-user",
            "New User"));

    assertEquals("Registration failed: user information missing in response", ex.getMessage());
  }

  @Test
  void registerWithPasswordWithoutServiceRoleRejectsInvalidTokenPayload() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> clientWithoutServiceRoleKey.registerWithPassword(
            "invalid-signup@example.com",
            "password123",
            "new-user",
            "New User"));

    assertEquals(
        "Registration failed: invalid token payload from identity provider",
        ex.getMessage());
  }

  @Test
  void registerWithPasswordWithoutServiceRoleMapsRateLimitToHelpfulMessage() {
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> clientWithoutServiceRoleKey.registerWithPassword(
            "rate-limit@example.com",
            "password123",
            "new-user",
            "New User"));

    assertEquals(
        "email rate limit exceeded. Set SUPABASE_SERVICE_ROLE_KEY "
            + "or disable email confirmation in Supabase for dev",
        ex.getMessage());
  }

  @Test
  void registerWithPasswordWithoutServiceRoleMapsOtherClientErrorToIllegalArgumentException() {
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> clientWithoutServiceRoleKey.registerWithPassword(
            "bad-signup@example.com",
            "password123",
            "new-user",
            "New User"));

    assertEquals("Signup rejected", ex.getMessage());
  }

  @Test
  void registerWithPasswordWithoutServiceRoleMapsServerErrorToIllegalStateException() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> clientWithoutServiceRoleKey.registerWithPassword(
            "server-error-signup@example.com",
            "password123",
            "new-user",
            "New User"));

    assertEquals("Identity provider error while registration", ex.getMessage());
  }

  @Test
  void loginWithPasswordMapsClientErrorToUnauthorizedException() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.loginWithPassword("wrong@example.com", "wrong-password"));

    assertEquals("Invalid login credentials", ex.getMessage());
  }

  @Test
  void logoutSucceedsForValidToken() {
    assertDoesNotThrow(() -> client.logout("valid-logout-token"));
  }

  @Test
  void logoutMapsClientErrorToUnauthorizedException() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.logout("bad-logout-token"));

    assertEquals("Session not found", ex.getMessage());
  }

  @Test
  void logoutMapsServerErrorToIllegalStateException() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> client.logout("server-error-logout-token"));

    assertEquals("Identity provider error while logout", ex.getMessage());
  }

  @Test
  void updateEmailMapsClientErrorToUnauthorizedException() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.updateEmail("bad-email-token", "new@example.com"));

    assertEquals("Email update rejected", ex.getMessage());
  }

  @Test
  void updateEmailSucceedsForValidToken() {
    assertDoesNotThrow(() -> client.updateEmail("good-email-token", "new@example.com"));
  }

  @Test
  void updateEmailMapsServerErrorToIllegalStateException() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> client.updateEmail("server-error-email-token", "new@example.com"));

    assertEquals("Identity provider error while updating email", ex.getMessage());
  }

  @Test
  void updatePasswordMapsServerErrorToIllegalStateException() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> client.updatePassword("server-error-password-token", "password123"));

    assertEquals("Identity provider error while updating password", ex.getMessage());
  }

  @Test
  void updatePasswordMapsClientErrorToUnauthorizedException() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.updatePassword("bad-password-token", "password123"));

    assertEquals("Password update rejected", ex.getMessage());
  }

  @Test
  void updatePasswordSucceedsForValidToken() {
    assertDoesNotThrow(() -> client.updatePassword("good-password-token", "password123"));
  }

  @Test
  void loginRejectsMissingConfiguration() {
    HttpSupabaseAuthClient missingConfigClient = new HttpSupabaseAuthClient("", "", "");

    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> missingConfigClient.loginWithPassword("user@example.com", "password123"));

    assertEquals("supabase.url must be configured", ex.getMessage());
  }

  @Test
  void loginRejectsMissingApiKeyConfiguration() {
    HttpSupabaseAuthClient missingApiKeyClient =
        new HttpSupabaseAuthClient("http://localhost", "", "");

    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> missingApiKeyClient.loginWithPassword("user@example.com", "password123"));

    assertEquals("supabase.api-key must be configured", ex.getMessage());
  }

  @Test
  void adminLookupRejectsMissingServiceRoleConfiguration() {
    IllegalStateException ex = assertThrows(
        IllegalStateException.class,
        () -> clientWithoutServiceRoleKey.getUserById("user-123"));

    assertEquals("supabase.service-role-key must be configured", ex.getMessage());
  }

  private static class AdminUserHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      String path = exchange.getRequestURI().getPath();
      String userId = path.substring(path.lastIndexOf('/') + 1);

      if ("missing-user".equals(userId)) {
        writeJson(
            exchange,
            404,
            """
            {
              "message": "User not found"
            }
            """);
        return;
      }

      if ("server-error-user".equals(userId)) {
        writeJson(
            exchange,
            500,
            """
            {
              "message": "Server error"
            }
            """);
        return;
      }

      if ("empty-user".equals(userId)) {
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
        return;
      }

      if ("invalid-user".equals(userId)) {
        writeJson(
            exchange,
            200,
            """
            {
              "id": "invalid-user"
            }
            """);
        return;
      }

      if ("/auth/v1/admin/users".equals(path)) {
        writeJson(
            exchange,
            400,
            """
            {
              "message": "User already registered"
            }
            """);
        return;
      }

      writeJson(
          exchange,
          200,
          """
          {
            "id": "user-123",
            "email": "admin@example.com",
            "app_metadata": {
              "role": "admin",
              "provider": "google"
            },
            "identities": [
              {
                "provider": "google",
                "id": "google-sub-123"
              }
            ],
            "user_metadata": {
              "display_name": "Admin User"
            }
          }
          """);
    }
  }

  private static class TokenHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      String grantType = exchange.getRequestURI().getQuery();
      String requestBody;
      try (InputStream body = exchange.getRequestBody()) {
        requestBody = new String(body.readAllBytes(), StandardCharsets.UTF_8);
      }

      byte[] responseBody;
      int statusCode = 200;
      if ("grant_type=password".equals(grantType)
          && requestBody.contains("\"wrong@example.com\"")) {
        statusCode = 400;
        responseBody =
            """
            {
              "message": "Invalid login credentials"
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else if ("grant_type=password".equals(grantType)
          && requestBody.contains("\"empty@example.com\"")) {
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
        return;
      } else if ("grant_type=password".equals(grantType)
          && requestBody.contains("\"missing-user@example.com\"")) {
        responseBody =
            """
            {
              "access_token": "access-token"
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else if ("grant_type=password".equals(grantType)
          && requestBody.contains("\"invalid-token@example.com\"")) {
        responseBody =
            """
            {
              "access_token": "",
              "user": {
                "id": ""
              }
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else if ("grant_type=password".equals(grantType)
          && requestBody.contains("\"server-error@example.com\"")) {
        statusCode = 500;
        responseBody =
            """
            {
              "message": "Login server failed"
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else if ("grant_type=password".equals(grantType)) {
        responseBody =
            """
            {
              "access_token": "access-token",
              "refresh_token": "refresh-token",
              "expires_in": 3600,
              "user": {
                "id": "user-456",
                "email": "user@example.com",
                "app_metadata": {
                  "role": "student"
                }
              }
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else if ("grant_type=refresh_token".equals(grantType)
          && requestBody.contains("\"bad-refresh-token\"")) {
        statusCode = 400;
        responseBody =
            """
            {
              "message": "Refresh token invalid"
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else if ("grant_type=refresh_token".equals(grantType)
          && requestBody.contains("\"empty-refresh-token\"")) {
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
        return;
      } else if ("grant_type=refresh_token".equals(grantType)
          && requestBody.contains("\"missing-user-refresh-token\"")) {
        responseBody =
            """
            {
              "access_token": "refreshed-access-token"
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else if ("grant_type=refresh_token".equals(grantType)
          && requestBody.contains("\"invalid-refresh-token\"")) {
        responseBody =
            """
            {
              "access_token": "",
              "user": {
                "id": ""
              }
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else if ("grant_type=refresh_token".equals(grantType)
          && requestBody.contains("\"server-error-refresh-token\"")) {
        statusCode = 500;
        responseBody =
            """
            {
              "message": "Refresh server failed"
            }
            """.getBytes(StandardCharsets.UTF_8);
      } else {
        responseBody =
            """
            {
              "access_token": "refreshed-access-token",
              "refresh_token": "refreshed-refresh-token",
              "expires_in": 7200,
              "user": {
                "id": "user-789",
                "email": "refresh@example.com",
                "app_metadata": {
                  "role": "admin"
                }
              }
            }
            """.getBytes(StandardCharsets.UTF_8);
      }

      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(statusCode, responseBody.length);
      try (OutputStream outputStream = exchange.getResponseBody()) {
        outputStream.write(responseBody);
      }
    }
  }

  private static class SignupHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      String requestBody;
      try (InputStream body = exchange.getRequestBody()) {
        requestBody = new String(body.readAllBytes(), StandardCharsets.UTF_8);
      }

      if (requestBody.contains("\"empty-signup@example.com\"")) {
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
        return;
      }

      if (requestBody.contains("\"plain@example.com\"")) {
        writeJson(
            exchange,
            200,
            """
            {
              "access_token": "signup-access-token-plain",
              "refresh_token": "signup-refresh-token-plain",
              "expires_in": 3600,
              "user": {
                "id": "signup-user-plain",
                "email": "plain@example.com"
              }
            }
            """);
        return;
      }

      if (requestBody.contains("\"missing-signup-user@example.com\"")) {
        writeJson(
            exchange,
            200,
            """
            {
              "access_token": "signup-access-token"
            }
            """);
        return;
      }

      if (requestBody.contains("\"invalid-signup@example.com\"")) {
        writeJson(
            exchange,
            200,
            """
            {
              "access_token": "signup-access-token",
              "user": {
                "id": ""
              }
            }
            """);
        return;
      }

      if (requestBody.contains("\"rate-limit@example.com\"")) {
        writeJson(
            exchange,
            400,
            """
            {
              "message": "Email rate limit exceeded"
            }
            """);
        return;
      }

      if (requestBody.contains("\"bad-signup@example.com\"")) {
        writeJson(
            exchange,
            400,
            """
            {
              "message": "Signup rejected"
            }
            """);
        return;
      }

      if (requestBody.contains("\"server-error-signup@example.com\"")) {
        writeJson(
            exchange,
            500,
            """
            {
              "message": "Signup server failed"
            }
            """);
        return;
      }

      writeJson(
          exchange,
          200,
          """
          {
            "access_token": "signup-access-token",
            "refresh_token": "signup-refresh-token",
            "expires_in": 3600,
            "user": {
              "id": "signup-user-1",
              "email": "new@example.com",
              "app_metadata": {
                "role": "student"
              }
            }
          }
          """);
    }
  }

  private static class LogoutHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      String authorization = exchange.getRequestHeaders().getFirst("Authorization");
      if ("Bearer bad-logout-token".equals(authorization)) {
        writeJson(
            exchange,
            400,
            """
            {
              "message": "Session not found"
            }
            """);
        return;
      }

      if ("Bearer server-error-logout-token".equals(authorization)) {
        writeJson(
            exchange,
            500,
            """
            {
              "message": "Logout server failed"
            }
            """);
        return;
      }

      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    }
  }

  private static class UserUpdateHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      String authorization = exchange.getRequestHeaders().getFirst("Authorization");
      if ("Bearer bad-email-token".equals(authorization)) {
        writeJson(
            exchange,
            400,
            """
            {
              "message": "Email update rejected"
            }
            """);
        return;
      }

      if ("Bearer server-error-email-token".equals(authorization)) {
        writeJson(
            exchange,
            500,
            """
            {
              "message": "Email service failed"
            }
            """);
        return;
      }

      if ("Bearer bad-password-token".equals(authorization)) {
        writeJson(
            exchange,
            400,
            """
            {
              "message": "Password update rejected"
            }
            """);
        return;
      }

      if ("Bearer server-error-password-token".equals(authorization)) {
        writeJson(
            exchange,
            500,
            """
            {
              "message": "Password service failed"
            }
            """);
        return;
      }

      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    }
  }

  private static void writeJson(HttpExchange exchange, int statusCode, String response)
      throws IOException {
    byte[] responseBody = response.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(statusCode, responseBody.length);
    try (OutputStream outputStream = exchange.getResponseBody()) {
      outputStream.write(responseBody);
    }
  }
}


