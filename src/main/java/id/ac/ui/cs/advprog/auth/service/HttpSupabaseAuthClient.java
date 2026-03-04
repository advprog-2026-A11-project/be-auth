package id.ac.ui.cs.advprog.auth.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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
  private final String supabaseApiKey;
  private final String supabaseServiceRoleKey;
  private final RestClient restClient;
  private final ObjectMapper objectMapper;

  public HttpSupabaseAuthClient(
      @Value("${supabase.url:}") String supabaseUrl,
      @Value("${supabase.api-key:${supabase.anon-key:}}") String supabaseApiKey,
      @Value("${supabase.service-role-key:}") String supabaseServiceRoleKey) {
    this.supabaseUrl = supabaseUrl;
    this.supabaseApiKey = supabaseApiKey;
    this.supabaseServiceRoleKey = supabaseServiceRoleKey;
    this.restClient = RestClient.builder().build();
    this.objectMapper = new ObjectMapper();
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
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseApiKey)
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
        String detail = extractSupabaseErrorMessage(ex.getResponseBodyAsString());
        throw new UnauthorizedException(detail);
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
    if (StringUtils.hasText(supabaseServiceRoleKey)) {
      return registerViaAdminApi(email, password, username, displayName);
    }

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
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseApiKey)
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
        String detail = extractSupabaseErrorMessage(ex.getResponseBodyAsString());
        if (isEmailRateLimit(detail)) {
          if (StringUtils.hasText(supabaseServiceRoleKey)) {
            return registerViaAdminApi(email, password, username, displayName);
          }
          throw new IllegalArgumentException(
              "email rate limit exceeded. Set SUPABASE_SERVICE_ROLE_KEY "
                  + "or disable email confirmation in Supabase for dev");
        }
        if (detail.toLowerCase().contains("already registered")) {
          throw new ConflictException("Email already registered");
        }
        throw new IllegalArgumentException(detail);
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
    if (!StringUtils.hasText(supabaseApiKey)) {
      throw new IllegalStateException("supabase.api-key must be configured");
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

  private String extractSupabaseErrorMessage(String body) {
    if (!StringUtils.hasText(body)) {
      return "Invalid registration payload";
    }

    try {
      Map<String, Object> parsed = objectMapper.readValue(
          body,
          new TypeReference<Map<String, Object>>() {});
      String message = firstNonBlank(
          parsed.get("msg"),
          parsed.get("message"),
          parsed.get("error_description"),
          parsed.get("error"));
      return StringUtils.hasText(message) ? message : "Invalid registration payload";
    } catch (Exception ignored) {
      return body.length() > 200 ? body.substring(0, 200) : body;
    }
  }

  private String firstNonBlank(Object... candidates) {
    for (Object candidate : candidates) {
      if (candidate == null) {
        continue;
      }
      String value = String.valueOf(candidate).trim();
      if (StringUtils.hasText(value)) {
        return value;
      }
    }
    return "";
  }

  private boolean isEmailRateLimit(String detail) {
    return StringUtils.hasText(detail)
        && detail.toLowerCase().contains("email rate limit exceeded");
  }

  @SuppressWarnings("unchecked")
  private LoginResult registerViaAdminApi(
      String email,
      String password,
      String username,
      String displayName) {
    String adminUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/admin/users";
    Map<String, Object> requestPayload = new HashMap<>();
    requestPayload.put("email", email);
    requestPayload.put("password", password);
    requestPayload.put("email_confirm", true);

    Map<String, String> metadata = new HashMap<>();
    if (StringUtils.hasText(username)) {
      metadata.put("username", username.trim());
    }
    if (StringUtils.hasText(displayName)) {
      metadata.put("display_name", displayName.trim());
    }
    if (!metadata.isEmpty()) {
      requestPayload.put("user_metadata", metadata);
    }

    try {
      Map<String, Object> responseBody = restClient.post()
          .uri(adminUrl)
          .header("apikey", supabaseServiceRoleKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseServiceRoleKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .body(Map.class);

      if (responseBody == null) {
        throw new IllegalStateException("Registration failed via admin API");
      }

      String createdEmail = stringValue(responseBody.get("email"));
      if (!StringUtils.hasText(createdEmail)) {
        throw new IllegalStateException("Registration failed via admin API");
      }

      // Sign in using regular auth flow to obtain access token response.
      return loginWithPassword(createdEmail, password);
    } catch (HttpStatusCodeException ex) {
      String detail = extractSupabaseErrorMessage(ex.getResponseBodyAsString());
      if (detail.toLowerCase().contains("already")) {
        throw new ConflictException("Email already registered");
      }
      throw new IllegalArgumentException(detail);
    }
  }
}
