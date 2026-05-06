package id.ac.ui.cs.advprog.auth.service.supabase;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import java.util.List;
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
  public SupabaseAuthClient.IdentityUser getUserById(String supabaseUserId) {
    ensureAdminConfig();

    String userUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/admin/users/" + supabaseUserId;

    try {
      IdentityPayload responseBody = restClient.get()
          .uri(userUrl)
          .header("apikey", supabaseServiceRoleKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseServiceRoleKey)
          .accept(MediaType.APPLICATION_JSON)
          .retrieve()
          .body(IdentityPayload.class);

      if (responseBody == null) {
        throw new IllegalStateException(
            "User lookup failed: empty response from identity provider");
      }

      String resolvedSupabaseUserId = responseBody.id();
      String resolvedEmail = responseBody.email();
      String resolvedRole = readRole(responseBody);
      String authProvider = readAuthProvider(responseBody);
      String googleSub = readGoogleSub(responseBody);
      String displayName = readDisplayName(responseBody);

      if (!StringUtils.hasText(resolvedSupabaseUserId) || !StringUtils.hasText(resolvedEmail)) {
        throw new IllegalStateException("User lookup failed: invalid identity payload");
      }

      return new SupabaseAuthClient.IdentityUser(
          resolvedSupabaseUserId,
          resolvedEmail,
          resolvedRole,
          authProvider,
          googleSub,
          displayName);
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        String detail = extractSupabaseErrorMessage(ex.getResponseBodyAsString());
        throw new IllegalArgumentException(detail);
      }
      throw new IllegalStateException("Identity provider error while loading user", ex);
    }
  }

  @Override
  public LoginResult loginWithPassword(String email, String password) {
    ensureConfig();

    String tokenUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/token?grant_type=password";
    PasswordLoginRequest requestPayload = new PasswordLoginRequest(email, password);

    try {
      TokenPayload responseBody = restClient.post()
          .uri(tokenUrl)
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseApiKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .body(TokenPayload.class);

      if (responseBody == null) {
        throw new UnauthorizedException("Login failed: empty response from identity provider");
      }

      IdentityPayload userObject = responseBody.user();
      if (userObject == null) {
        throw new UnauthorizedException("Login failed: user information missing in response");
      }

      String accessToken = responseBody.accessToken();
      String refreshToken = responseBody.refreshToken();
      Long expiresIn = responseBody.expiresIn();
      String supabaseUserId = userObject.id();
      String normalizedEmail = userObject.email();
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
  public LoginResult refreshSession(String refreshToken) {
    ensureConfig();

    String tokenUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/token?grant_type=refresh_token";
    RefreshTokenRequest requestPayload = new RefreshTokenRequest(refreshToken);

    try {
      TokenPayload responseBody = restClient.post()
          .uri(tokenUrl)
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseApiKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .body(TokenPayload.class);

      if (responseBody == null) {
        throw new UnauthorizedException("Refresh failed: empty response from identity provider");
      }

      IdentityPayload userObject = responseBody.user();
      if (userObject == null) {
        throw new UnauthorizedException("Refresh failed: user information missing in response");
      }

      String accessToken = responseBody.accessToken();
      String newRefreshToken = responseBody.refreshToken();
      Long expiresIn = responseBody.expiresIn();
      String supabaseUserId = userObject.id();
      String normalizedEmail = userObject.email();
      String role = readRole(userObject);

      if (!StringUtils.hasText(accessToken) || !StringUtils.hasText(supabaseUserId)) {
        throw new UnauthorizedException(
            "Refresh failed: invalid token payload from identity provider");
      }

      return new LoginResult(
          accessToken,
          newRefreshToken,
          expiresIn,
          supabaseUserId,
          normalizedEmail,
          role);
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        String detail = extractSupabaseErrorMessage(ex.getResponseBodyAsString());
        throw new UnauthorizedException(detail);
      }
      throw new IllegalStateException("Identity provider error while refreshing session", ex);
    }
  }

  @Override
  public void logout(String accessToken) {
    ensureConfig();

    String logoutUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/logout?scope=local";

    try {
      restClient.post()
          .uri(logoutUrl)
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
          .accept(MediaType.APPLICATION_JSON)
          .retrieve()
          .toBodilessEntity();
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        String detail = extractSupabaseErrorMessage(ex.getResponseBodyAsString());
        throw new UnauthorizedException(detail);
      }
      throw new IllegalStateException("Identity provider error while logout", ex);
    }
  }

  @Override
  public void updateEmail(String accessToken, String newEmail) {
    ensureConfig();

    String userUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/user";
    EmailUpdateRequest requestPayload = new EmailUpdateRequest(newEmail);

    try {
      restClient.put()
          .uri(userUrl)
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .toBodilessEntity();
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        String detail = extractSupabaseErrorMessage(ex.getResponseBodyAsString());
        throw new UnauthorizedException(detail);
      }
      throw new IllegalStateException("Identity provider error while updating email", ex);
    }
  }

  @Override
  public void updatePassword(String accessToken, String newPassword) {
    ensureConfig();

    String userUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/user";
    PasswordUpdateRequest requestPayload = new PasswordUpdateRequest(newPassword);

    try {
      restClient.put()
          .uri(userUrl)
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .toBodilessEntity();
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        String detail = extractSupabaseErrorMessage(ex.getResponseBodyAsString());
        throw new UnauthorizedException(detail);
      }
      throw new IllegalStateException("Identity provider error while updating password", ex);
    }
  }

  @Override
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
    SignupRequest requestPayload = new SignupRequest(
        email,
        password,
        buildUserMetadata(username, displayName));

    try {
      TokenPayload responseBody = restClient.post()
          .uri(registerUrl)
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseApiKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .body(TokenPayload.class);

      if (responseBody == null) {
        throw new IllegalStateException(
            "Registration failed: empty response from identity provider");
      }

      IdentityPayload userObject = responseBody.user();
      if (userObject == null) {
        throw new IllegalStateException(
            "Registration failed: user information missing in response");
      }

      String accessToken = responseBody.accessToken();
      String refreshToken = responseBody.refreshToken();
      Long expiresIn = responseBody.expiresIn();
      String supabaseUserId = userObject.id();
      String normalizedEmail = userObject.email();
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

  private UserMetadataPayload buildUserMetadata(String username, String displayName) {
    if (!StringUtils.hasText(username) && !StringUtils.hasText(displayName)) {
      return null;
    }

    return new UserMetadataPayload(
        normalizeOptional(username),
        normalizeOptional(displayName));
  }

  private void ensureConfig() {
    if (!StringUtils.hasText(supabaseUrl)) {
      throw new IllegalStateException("supabase.url must be configured");
    }
    if (!StringUtils.hasText(supabaseApiKey)) {
      throw new IllegalStateException("supabase.api-key must be configured");
    }
  }

  private void ensureAdminConfig() {
    ensureConfig();
    if (!StringUtils.hasText(supabaseServiceRoleKey)) {
      throw new IllegalStateException("supabase.service-role-key must be configured");
    }
  }

  private String trimTrailingSlash(String value) {
    if (!StringUtils.hasText(value)) {
      return value;
    }
    return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
  }

  private String extractSupabaseErrorMessage(String body) {
    if (!StringUtils.hasText(body)) {
      return "Invalid registration payload";
    }

    try {
      ErrorPayload parsed = objectMapper.readValue(body, ErrorPayload.class);
      String message = firstNonBlank(
          parsed.msg(),
          parsed.message(),
          parsed.errorDescription(),
          parsed.error());
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

  private String readRole(IdentityPayload userObject) {
    AppMetadataPayload metadata = userObject.appMetadata();
    if (metadata != null && StringUtils.hasText(metadata.role())) {
      return metadata.role();
    }

    return "";
  }

  private String readAuthProvider(IdentityPayload userObject) {
    AppMetadataPayload metadata = userObject.appMetadata();
    if (metadata != null && StringUtils.hasText(metadata.provider())) {
      return metadata.provider();
    }

    if (userObject.identities() != null) {
      for (IdentityProviderPayload identity : userObject.identities()) {
        if (identity != null && StringUtils.hasText(identity.provider())) {
          return identity.provider();
        }
      }
    }

    return "";
  }

  private String readGoogleSub(IdentityPayload userObject) {
    if (userObject.identities() != null) {
      for (IdentityProviderPayload identity : userObject.identities()) {
        if (identity != null
            && "google".equalsIgnoreCase(identity.provider())
            && StringUtils.hasText(identity.id())) {
          return identity.id();
        }
      }
    }

    return "";
  }

  private String readDisplayName(IdentityPayload userObject) {
    UserMetadataPayload userMetadata = userObject.userMetadata();
    if (userMetadata == null) {
      return "";
    }

    String displayName = firstNonBlank(
        userMetadata.displayName(),
        userMetadata.fullName(),
        userMetadata.name());
    if (StringUtils.hasText(displayName)) {
      return displayName;
    }

    return "";
  }

  private LoginResult registerViaAdminApi(
      String email,
      String password,
      String username,
      String displayName) {
    String adminUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/admin/users";
    AdminCreateUserRequest requestPayload = new AdminCreateUserRequest(
        email,
        password,
        true,
        buildUserMetadata(username, displayName));

    try {
      IdentityPayload responseBody = restClient.post()
          .uri(adminUrl)
          .header("apikey", supabaseServiceRoleKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseServiceRoleKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(requestPayload)
          .retrieve()
          .body(IdentityPayload.class);

      if (responseBody == null) {
        throw new IllegalStateException("Registration failed via admin API");
      }

      String createdEmail = responseBody.email();
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

  private String normalizeOptional(String value) {
    return StringUtils.hasText(value) ? value.trim() : null;
  }

  private record PasswordLoginRequest(String email, String password) {
  }

  private record RefreshTokenRequest(@JsonProperty("refresh_token") String refreshToken) {
  }

  private record EmailUpdateRequest(String email) {
  }

  private record PasswordUpdateRequest(String password) {
  }

  private record SignupRequest(
      String email,
      String password,
      @JsonProperty("data") UserMetadataPayload data) {
  }

  private record AdminCreateUserRequest(
      String email,
      String password,
      @JsonProperty("email_confirm") boolean emailConfirm,
      @JsonProperty("user_metadata") UserMetadataPayload userMetadata) {
  }

  private record TokenPayload(
      @JsonProperty("access_token") String accessToken,
      @JsonProperty("refresh_token") String refreshToken,
      @JsonProperty("expires_in") Long expiresIn,
      IdentityPayload user) {
  }

  private record IdentityPayload(
      String id,
      String email,
      @JsonProperty("app_metadata") AppMetadataPayload appMetadata,
      List<IdentityProviderPayload> identities,
      @JsonProperty("user_metadata") UserMetadataPayload userMetadata) {
  }

  private record AppMetadataPayload(String role, String provider) {
  }

  private record IdentityProviderPayload(String provider, String id) {
  }

  private record UserMetadataPayload(
      String username,
      @JsonProperty("display_name") String displayName,
      @JsonProperty("full_name") String fullName,
      String name) {
    private UserMetadataPayload(String username, String displayName) {
      this(username, displayName, null, null);
    }
  }

  private record ErrorPayload(
      String msg,
      String message,
      @JsonProperty("error_description") String errorDescription,
      String error) {
  }
}


