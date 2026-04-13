package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class SupabaseGoogleSsoService implements GoogleSsoService {

  private final String supabaseUrl;
  private final String supabaseApiKey;
  private final String redirectUrl;
  private final long stateTtlSeconds;
  private final SupabaseJwtService supabaseJwtService;
  private final UserProfileService userProfileService;
  private final AuthSessionService authSessionService;
  private final RestClient restClient;
  private final SecureRandom secureRandom = new SecureRandom();
  private final ConcurrentMap<String, PkceFlowState> pkceStates = new ConcurrentHashMap<>();

  public SupabaseGoogleSsoService(
      @Value("${supabase.url:}") String supabaseUrl,
      @Value("${supabase.api-key:${supabase.anon-key:}}") String supabaseApiKey,
      @Value("${auth.sso.google.redirect-url:}") String redirectUrl,
      @Value("${auth.sso.state-ttl-seconds:600}") long stateTtlSeconds,
      SupabaseJwtService supabaseJwtService,
      UserProfileService userProfileService,
      AuthSessionService authSessionService) {
    this.supabaseUrl = supabaseUrl;
    this.supabaseApiKey = supabaseApiKey;
    this.redirectUrl = redirectUrl;
    this.stateTtlSeconds = stateTtlSeconds;
    this.supabaseJwtService = supabaseJwtService;
    this.userProfileService = userProfileService;
    this.authSessionService = authSessionService;
    this.restClient = RestClient.builder().build();
  }

  @Override
  public SsoUrlResponse createSsoUrl() {
    return createSsoUrl(null);
  }

  @Override
  public SsoUrlResponse createSsoUrl(String redirectTo) {
    ensureConfig();
    cleanupExpiredStates();

    String flowId = UUID.randomUUID().toString();
    String codeVerifier = generateCodeVerifier();
    String codeChallenge = toS256CodeChallenge(codeVerifier);
    Instant expiresAt = Instant.now().plusSeconds(stateTtlSeconds);
    String targetRedirectUrl = resolveRedirectUrl(redirectTo);
    String callbackRedirectUrl = withAppState(targetRedirectUrl, flowId);
    pkceStates.put(flowId, new PkceFlowState(codeVerifier, expiresAt, callbackRedirectUrl));

    String authorizeUrl = UriComponentsBuilder
        .fromHttpUrl(trimTrailingSlash(supabaseUrl) + "/auth/v1/authorize")
        .queryParam("provider", "google")
        .queryParam("redirect_to", callbackRedirectUrl)
        .queryParam("code_challenge", codeChallenge)
        .queryParam("code_challenge_method", "s256")
        .build(false)
        .encode()
        .toUriString();

    return new SsoUrlResponse("google", authorizeUrl, "Google SSO URL generated");
  }

  @Override
  @SuppressWarnings("unchecked")
  public SsoCallbackResponse handleCallback(SsoCallbackRequest request) {
    ensureConfig();
    cleanupExpiredStates();

    PkceFlowState flowState = pkceStates.remove(request.state());
    if (flowState == null || flowState.expiresAt().isBefore(Instant.now())) {
      throw new UnauthorizedException("Invalid or expired SSO state");
    }

    String tokenUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/token?grant_type=pkce";
    Map<String, String> payload = Map.of(
        "auth_code", request.code(),
        "code_verifier", flowState.codeVerifier(),
        "redirect_to", flowState.redirectUrl());

    try {
      Map<String, Object> tokenResponse = restClient.post()
          .uri(tokenUrl)
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseApiKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(payload)
          .retrieve()
          .body(Map.class);

      if (tokenResponse == null) {
        throw new UnauthorizedException("Invalid SSO callback response");
      }

      String accessToken = asString(tokenResponse.get("access_token"));
      if (!StringUtils.hasText(accessToken)) {
        throw new UnauthorizedException("Missing access token from SSO callback");
      }

      Jwt jwt = supabaseJwtService.validateAccessToken(accessToken);
      String sub = jwt.getSubject();
      String email = jwt.getClaimAsString("email");
      String role = jwt.getClaimAsString("role");
      String displayName = extractDisplayName(jwt);

      if (!StringUtils.hasText(sub)) {
        throw new UnauthorizedException("SSO callback token missing subject");
      }

      ensureIdentityIsActive(accessToken, sub, email);
      String refreshToken = asString(tokenResponse.get("refresh_token"));

      boolean linked = isExistingIdentity(sub, email);
      UserProfile profile = userProfileService.upsertFromIdentity(
          sub,
          email,
          role,
          "GOOGLE",
          sub,
          displayName);

      return new SsoCallbackResponse(
          accessToken,
          refreshToken,
          profile.getSupabaseUserId(),
          linked,
          "Google SSO login successful");
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        throw new UnauthorizedException("Invalid SSO callback code");
      }
      throw new IllegalStateException("Identity provider error while processing SSO callback", ex);
    }
  }

  private boolean isExistingIdentity(String sub, String email) {
    Optional<UserProfile> bySub = userProfileService.findBySupabaseUserId(sub);
    if (bySub.isPresent()) {
      return true;
    }
    return StringUtils.hasText(email) && userProfileService.findByEmail(email).isPresent();
  }

  private void ensureIdentityIsActive(String accessToken, String sub, String email) {
    Optional<UserProfile> existing = userProfileService.findBySupabaseUserId(sub);
    if (existing.isEmpty() && StringUtils.hasText(email)) {
      existing = userProfileService.findByEmail(email);
    }

    if (existing.isPresent() && !existing.get().isActive()) {
      authSessionService.logout(accessToken);
      throw new UnauthorizedException("Account is inactive");
    }
  }

  private void cleanupExpiredStates() {
    Instant now = Instant.now();
    pkceStates.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
  }

  private String generateCodeVerifier() {
    byte[] buffer = new byte[64];
    secureRandom.nextBytes(buffer);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
  }

  private String toS256CodeChallenge(String codeVerifier) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hashed = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 algorithm not available", ex);
    }
  }

  private void ensureConfig() {
    if (!StringUtils.hasText(supabaseUrl)) {
      throw new IllegalStateException("supabase.url must be configured");
    }
    if (!StringUtils.hasText(supabaseApiKey)) {
      throw new IllegalStateException("supabase.api-key must be configured");
    }
    if (!StringUtils.hasText(redirectUrl)) {
      throw new IllegalStateException("auth.sso.google.redirect-url must be configured");
    }
  }

  private String resolveRedirectUrl(String requestedRedirectUrl) {
    if (!StringUtils.hasText(requestedRedirectUrl)) {
      return redirectUrl;
    }
    String candidate = requestedRedirectUrl.trim();
    if (candidate.startsWith("http://") || candidate.startsWith("https://")) {
      return candidate;
    }
    throw new IllegalArgumentException("redirectTo must start with http:// or https://");
  }

  private String withAppState(String baseRedirectUrl, String flowId) {
    return UriComponentsBuilder.fromUriString(baseRedirectUrl)
        .replaceQueryParam("app_state", flowId)
        .build(true)
        .toUriString();
  }

  private String trimTrailingSlash(String value) {
    if (!StringUtils.hasText(value)) {
      return value;
    }
    return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
  }

  private String asString(Object value) {
    return value == null ? "" : String.valueOf(value);
  }

  @SuppressWarnings("unchecked")
  private String extractDisplayName(Jwt jwt) {
    String fullName = jwt.getClaimAsString("full_name");
    if (StringUtils.hasText(fullName)) {
      return fullName.trim();
    }

    String name = jwt.getClaimAsString("name");
    if (StringUtils.hasText(name)) {
      return name.trim();
    }

    Object userMetadata = jwt.getClaims().get("user_metadata");
    if (userMetadata instanceof Map<?, ?> metadata) {
      Object metadataName = metadata.get("full_name");
      if (metadataName == null) {
        metadataName = metadata.get("name");
      }
      if (metadataName != null && StringUtils.hasText(String.valueOf(metadataName))) {
        return String.valueOf(metadataName).trim();
      }
    }

    return "";
  }

  private record PkceFlowState(String codeVerifier, Instant expiresAt, String redirectUrl) {
  }
}
