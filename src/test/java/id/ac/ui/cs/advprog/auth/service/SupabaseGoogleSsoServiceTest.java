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
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.io.IOException;
import java.io.InputStream;
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

  private static final String CALLBACK_URL = "http://localhost:3000/users/account";

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
        CALLBACK_URL,
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
  void createSsoUrlDelegatesFlowStateThroughRedirectTarget() {
    SsoUrlResponse response = service.createSsoUrl(CALLBACK_URL);

    assertEquals(true, response.authorizationUrl().contains("redirect_to="));
    assertEquals(false, response.authorizationUrl().contains("&state="));
    assertEquals(false, response.authorizationUrl().contains("?state="));
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

    assertEquals(
        "Your account has been banned. Please contact an administrator.",
        ex.getMessage());
    verify(authSessionService).logout("access-token");
  }

  @Test
  void handleCallbackPassesGoogleIdentityEnrichmentToProfileSync() {
    Jwt jwt = new Jwt(
        "access-token",
        Instant.now(),
        Instant.now().plusSeconds(3600),
        Map.of("alg", "none"),
        Map.of(
            "sub", "google-sub-123",
            "email", "google@example.com",
            "role", "authenticated",
            "full_name", "Google User",
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));
    when(supabaseJwtService.validateAccessToken("access-token")).thenReturn(jwt);
    when(userProfileService.findBySupabaseUserId("google-sub-123")).thenReturn(Optional.empty());
    when(userProfileService.findByEmail("google@example.com")).thenReturn(Optional.empty());

    UserProfile profile = new UserProfile();
    profile.setId(java.util.UUID.randomUUID());
    profile.setSupabaseUserId("google-sub-123");
    when(userProfileService.upsertFromIdentity(
        "google-sub-123",
        "google@example.com",
        "authenticated",
        "GOOGLE",
        "google-sub-123",
        "Google User")).thenReturn(profile);

    SsoCallbackResponse response =
        service.handleCallback(new SsoCallbackRequest("oauth-code", "opaque-state"));

    assertEquals(profile.getId().toString(), response.userId());
    assertEquals(false, response.linked());
  }

  @Test
  void handleCallbackUsesStoredRedirectUrlForPkceExchange() {
    TokenHandler.lastRequestBody = "";

    Jwt jwt = new Jwt(
        "access-token",
        Instant.now(),
        Instant.now().plusSeconds(3600),
        Map.of("alg", "none"),
        Map.of(
            "sub", "redirect-sub-123",
            "email", "redirect@example.com",
            "role", "authenticated",
            "aud", List.of("authenticated"),
            "iss", "https://supabase.test/auth/v1"));
    when(supabaseJwtService.validateAccessToken("access-token")).thenReturn(jwt);
    when(userProfileService.findBySupabaseUserId("redirect-sub-123")).thenReturn(Optional.empty());
    when(userProfileService.findByEmail("redirect@example.com")).thenReturn(Optional.empty());

    UserProfile profile = new UserProfile();
    profile.setId(java.util.UUID.randomUUID());
    profile.setSupabaseUserId("redirect-sub-123");
    when(userProfileService.upsertFromIdentity(
        "redirect-sub-123",
        "redirect@example.com",
        "authenticated",
        "GOOGLE",
        "redirect-sub-123",
        "")).thenReturn(profile);

    service.handleCallback(new SsoCallbackRequest("oauth-code", "opaque-state"));

    assertEquals(true, TokenHandler.lastRequestBody.contains("redirect_to"));
    assertEquals(true, TokenHandler.lastRequestBody.contains("app_state"));
    assertEquals(true, TokenHandler.lastRequestBody.contains("opaque-state"));
  }

  @SuppressWarnings("unchecked")
  private void seedPkceState(String state) throws Exception {
    Field pkceStatesField = SupabaseGoogleSsoService.class.getDeclaredField("pkceStates");
    pkceStatesField.setAccessible(true);
    ConcurrentMap<String, Object> pkceStates =
        (ConcurrentMap<String, Object>) pkceStatesField.get(service);

    Class<?> stateClass = Class.forName(
        "id.ac.ui.cs.advprog.auth.service.SupabaseGoogleSsoService$PkceFlowState");
    var constructor = stateClass.getDeclaredConstructor(String.class, Instant.class, String.class);
    constructor.setAccessible(true);
    Object flowState = constructor.newInstance(
        "verifier",
        Instant.now().plusSeconds(300),
        CALLBACK_URL + "?app_state=" + state);
    pkceStates.put(state, flowState);
  }

  private static class TokenHandler implements HttpHandler {
    private static String lastRequestBody = "";

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      try (InputStream requestBody = exchange.getRequestBody()) {
        lastRequestBody = new String(requestBody.readAllBytes(), StandardCharsets.UTF_8);
      }
      byte[] response =
          """
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
