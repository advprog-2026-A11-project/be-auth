package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.jwt.Jwt;

class SupabaseGoogleSsoServiceTest {

  @Mock
  private SupabaseJwtService supabaseJwtService;

  @Mock
  private UserProfileService userProfileService;

  @Mock
  private AuthSessionService authSessionService;

  private HttpServer server;
  private SupabaseGoogleSsoService service;

  @BeforeEach
  void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    server = HttpServer.create(new InetSocketAddress(0), 0);
    server.createContext("/auth/v1/token", new TokenHandler());
    server.start();

    String baseUrl = "http://localhost:" + server.getAddress().getPort();
    service = new SupabaseGoogleSsoService(
        baseUrl,
        "anon-key",
        "http://localhost:3000/users/account",
        600,
        supabaseJwtService,
        userProfileService,
        authSessionService);

    seedPkceState("opaque-state");
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
  }

  @Test
  void handleCallbackRejectsInactiveExistingIdentity() {
    Jwt jwt = new Jwt(
        "access-token",
        Instant.now(),
        Instant.now().plusSeconds(3600),
        Map.of("alg", "none"),
        Map.of(
            "sub", "sub-inactive",
            "email", "inactive@example.com",
            "role", "authenticated",
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));
    when(supabaseJwtService.validateAccessToken("access-token")).thenReturn(jwt);

    UserProfile inactive = new UserProfile();
    inactive.setSupabaseUserId("sub-inactive");
    inactive.setEmail("inactive@example.com");
    inactive.setActive(false);
    when(userProfileService.findBySupabaseUserId("sub-inactive")).thenReturn(Optional.of(inactive));
    doNothing().when(authSessionService).logout("access-token");

    UnauthorizedException ex = assertThrows(
        UnauthorizedException.class,
        () -> service.handleCallback(new SsoCallbackRequest("oauth-code", "opaque-state")));

    assertEquals("Account is inactive", ex.getMessage());
    verify(authSessionService).logout("access-token");
  }

  @SuppressWarnings("unchecked")
  private void seedPkceState(String state) throws Exception {
    Field pkceStatesField = SupabaseGoogleSsoService.class.getDeclaredField("pkceStates");
    pkceStatesField.setAccessible(true);
    ConcurrentMap<String, Object> pkceStates =
        (ConcurrentMap<String, Object>) pkceStatesField.get(service);

    Class<?> stateClass = Class.forName(
        "id.ac.ui.cs.advprog.auth.service.SupabaseGoogleSsoService$PkceFlowState");
    var constructor = stateClass.getDeclaredConstructor(String.class, Instant.class);
    constructor.setAccessible(true);
    Object flowState = constructor.newInstance("verifier", Instant.now().plusSeconds(300));
    pkceStates.put(state, flowState);
  }

  private static class TokenHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
      byte[] response = """
          {
            "access_token": "access-token",
            "refresh_token": "refresh-token"
          }
          """.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, response.length);
      try (OutputStream outputStream = exchange.getResponseBody()) {
        outputStream.write(response);
      }
    }
  }
}
