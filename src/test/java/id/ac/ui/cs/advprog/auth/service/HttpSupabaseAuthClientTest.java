package id.ac.ui.cs.advprog.auth.service;

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

  @BeforeEach
  void setUp() throws Exception {
    server = HttpServer.create(new InetSocketAddress(0), 0);
    server.createContext("/auth/v1/admin/users/user-123", new JsonHandler(
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
        """));
    server.createContext("/auth/v1/token", new TokenHandler());
    server.createContext("/auth/v1/signup", new JsonHandler(
        400,
        """
        {
          "message": "User already registered"
        }
        """));
    server.createContext("/auth/v1/admin/users", new JsonHandler(
        400,
        """
        {
          "message": "User already registered"
        }
        """));
    server.start();

    String baseUrl = "http://localhost:" + server.getAddress().getPort();
    client = new HttpSupabaseAuthClient(baseUrl, "anon-key", "service-role-key");
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
  void loginWithPasswordMapsClientErrorToUnauthorizedException() {
    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> client.loginWithPassword("wrong@example.com", "wrong-password"));

    assertEquals("Invalid login credentials", ex.getMessage());
  }

  private static class JsonHandler implements HttpHandler {

    private final int statusCode;
    private final byte[] responseBody;

    private JsonHandler(int statusCode, String responseBody) {
      this.statusCode = statusCode;
      this.responseBody = responseBody.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(statusCode, responseBody.length);
      try (OutputStream outputStream = exchange.getResponseBody()) {
        outputStream.write(responseBody);
      }
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
}
