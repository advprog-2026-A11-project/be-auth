package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;

@Component
public class HttpSupabaseAuthClient implements SupabaseAuthClient {

  private final String supabaseUrl;
  private final String supabaseAnonKey;
  private final RestClient restClient;

  public HttpSupabaseAuthClient(
      @Value("${supabase.url:}") String supabaseUrl,
      @Value("${supabase.anon-key:}") String supabaseAnonKey) {
    this.supabaseUrl = supabaseUrl;
    this.supabaseAnonKey = supabaseAnonKey;
    this.restClient = RestClient.builder().build();
  }

  @Override
  @SuppressWarnings("unchecked")
  public LoginResult loginWithPassword(String email, String password) {
    ensureConfig();

    String tokenUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/token?grant_type=password";
    Map<String, String> requestPayload = Map.of(
        "email", email,
        "password", password);

    try {
      Map<String, Object> responseBody = restClient.post()
          .uri(tokenUrl)
          .header("apikey", supabaseAnonKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseAnonKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .body(Map.class);

      if (responseBody == null) {
        throw new UnauthorizedException("Login failed: empty response from identity provider");
      }

      Map<String, Object> userObject = (Map<String, Object>) responseBody.get("user");
      if (userObject == null) {
        throw new UnauthorizedException("Login failed: user information missing in response");
      }

      String accessToken = stringValue(responseBody.get("access_token"));
      String refreshToken = stringValue(responseBody.get("refresh_token"));
      Long expiresIn = longValue(responseBody.get("expires_in"));
      String supabaseUserId = stringValue(userObject.get("id"));
      String normalizedEmail = stringValue(userObject.get("email"));
      String role = readRole(userObject);

      if (!StringUtils.hasText(accessToken) || !StringUtils.hasText(supabaseUserId)) {
        throw new UnauthorizedException(
            "Login failed: invalid token payload from identity provider");
      }

      return new LoginResult(
          accessToken,
          refreshToken,
          expiresIn,
          supabaseUserId,
          normalizedEmail,
          role);
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        throw new UnauthorizedException("Invalid login credentials");
      }
      throw new IllegalStateException("Identity provider error while login", ex);
    }
  }

  @Override
  @SuppressWarnings("unchecked")
  public LoginResult registerWithPassword(
      String email,
      String password,
      String username,
      String displayName) {
    ensureConfig();

    String registerUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/signup";
    Map<String, Object> requestPayload = new HashMap<>();
    requestPayload.put("email", email);
    requestPayload.put("password", password);
    Map<String, String> metadata = new HashMap<>();
    if (StringUtils.hasText(username)) {
      metadata.put("username", username.trim());
    }
    if (StringUtils.hasText(displayName)) {
      metadata.put("display_name", displayName.trim());
    }
    if (!metadata.isEmpty()) {
      requestPayload.put("data", metadata);
    }

    try {
      Map<String, Object> responseBody = restClient.post()
          .uri(registerUrl)
          .header("apikey", supabaseAnonKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseAnonKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .body(Map.class);

      if (responseBody == null) {
        throw new IllegalStateException(
            "Registration failed: empty response from identity provider");
      }

      Map<String, Object> userObject = (Map<String, Object>) responseBody.get("user");
      if (userObject == null) {
        throw new IllegalStateException(
            "Registration failed: user information missing in response");
      }

      String accessToken = stringValue(responseBody.get("access_token"));
      String refreshToken = stringValue(responseBody.get("refresh_token"));
      Long expiresIn = longValue(responseBody.get("expires_in"));
      String supabaseUserId = stringValue(userObject.get("id"));
      String normalizedEmail = stringValue(userObject.get("email"));
      String role = readRole(userObject);

      if (!StringUtils.hasText(supabaseUserId)) {
        throw new IllegalStateException(
            "Registration failed: invalid token payload from identity provider");
      }

      return new LoginResult(
          accessToken,
          refreshToken,
          expiresIn,
          supabaseUserId,
          normalizedEmail,
          role);
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        String body = ex.getResponseBodyAsString();
        if (body != null && body.toLowerCase().contains("already registered")) {
          throw new ConflictException("Email already registered");
        }
        throw new IllegalArgumentException("Invalid registration payload");
      }
      throw new IllegalStateException("Identity provider error while registration", ex);
    }
  }

  @SuppressWarnings("unchecked")
  private String readRole(Map<String, Object> userObject) {
    Object appMetadataObj = userObject.get("app_metadata");
    if (appMetadataObj instanceof Map<?, ?> metadataMap) {
      return stringValue(((Map<String, Object>) metadataMap).get("role"));
    }
    return "";
  }

  private void ensureConfig() {
    if (!StringUtils.hasText(supabaseUrl)) {
      throw new IllegalStateException("supabase.url must be configured");
    }
    if (!StringUtils.hasText(supabaseAnonKey)) {
      throw new IllegalStateException("supabase.anon-key must be configured");
    }
  }

  private String trimTrailingSlash(String value) {
    if (!StringUtils.hasText(value)) {
      return value;
    }
    return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
  }

  private String stringValue(Object value) {
    return value == null ? "" : String.valueOf(value);
  }

  private Long longValue(Object value) {
    if (value instanceof Number number) {
      return number.longValue();
    }
    if (value == null) {
      return null;
    }
    try {
      return Long.parseLong(String.valueOf(value));
    } catch (NumberFormatException ex) {
      return null;
    }
  }
}
