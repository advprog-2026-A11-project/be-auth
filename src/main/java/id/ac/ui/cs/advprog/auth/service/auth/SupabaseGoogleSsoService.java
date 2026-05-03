package id.ac.ui.cs.advprog.auth.service.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthRequests.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.service.state.PkceStateStore;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseJwtService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
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
public class SupabaseGoogleSsoService {

  private final String supabaseUrl;
  private final String supabaseApiKey;
  private final String redirectUrl;
  private final long stateTtlSeconds;
  private final SupabaseJwtService supabaseJwtService;
  private final GoogleSsoIdentityService googleSsoIdentityService;
  private final PkceStateStore pkceStateStore;
  private final Clock clock;
  private final RestClient restClient;
  private final SecureRandom secureRandom = new SecureRandom();

  public SupabaseGoogleSsoService(
      @Value("${supabase.url:}") String supabaseUrl,
      @Value("${supabase.api-key:${supabase.anon-key:}}") String supabaseApiKey,
      @Value("${auth.sso.google.redirect-url:}") String redirectUrl,
      @Value("${auth.sso.state-ttl-seconds:600}") long stateTtlSeconds,
      SupabaseJwtService supabaseJwtService,
      GoogleSsoIdentityService googleSsoIdentityService,
      PkceStateStore pkceStateStore,
      Clock clock) {
    this.supabaseUrl = supabaseUrl;
    this.supabaseApiKey = supabaseApiKey;
    this.redirectUrl = redirectUrl;
    this.stateTtlSeconds = stateTtlSeconds;
    this.supabaseJwtService = supabaseJwtService;
    this.googleSsoIdentityService = googleSsoIdentityService;
    this.pkceStateStore = pkceStateStore;
    this.clock = clock;
    this.restClient = RestClient.builder().build();
  }

  public SsoUrlResponse createSsoUrl() {
    return createSsoUrl(null);
  }

  public SsoUrlResponse createSsoUrl(String redirectTo) {
    ensureConfig();

    String flowId = UUID.randomUUID().toString();
    String codeVerifier = generateCodeVerifier();
    String codeChallenge = toS256CodeChallenge(codeVerifier);
    Instant expiresAt = Instant.now(clock).plusSeconds(stateTtlSeconds);
    String targetRedirectUrl = resolveRedirectUrl(redirectTo);
    String callbackRedirectUrl = withAppState(targetRedirectUrl, flowId);
    pkceStateStore.save(flowId, codeVerifier, expiresAt, callbackRedirectUrl);

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

  @SuppressWarnings("unchecked")
  public SsoCallbackResponse handleCallback(SsoCallbackRequest request) {
    ensureConfig();

    Optional<PkceStateStore.PkceFlowState> flowState = pkceStateStore.take(
        request.state(),
        Instant.now(clock));
    if (flowState.isEmpty()) {
      throw new UnauthorizedException("Invalid or expired SSO state");
    }

    String tokenUrl = trimTrailingSlash(supabaseUrl) + "/auth/v1/token?grant_type=pkce";
    TokenExchangeRequest payload = new TokenExchangeRequest(
        request.code(),
        flowState.get().codeVerifier(),
        flowState.get().redirectUrl());

    try {
      TokenExchangeResponse tokenResponse = restClient.post()
          .uri(tokenUrl)
          .header("apikey", supabaseApiKey)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + supabaseApiKey)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(MediaType.APPLICATION_JSON)
          .body(payload)
          .retrieve()
          .body(TokenExchangeResponse.class);

      if (tokenResponse == null) {
        throw new UnauthorizedException("Invalid SSO callback response");
      }

      String accessToken = asString(tokenResponse.accessToken());
      if (!StringUtils.hasText(accessToken)) {
        throw new UnauthorizedException("Missing access token from SSO callback");
      }

      Jwt jwt = supabaseJwtService.validateAccessToken(accessToken);
      String refreshToken = asString(tokenResponse.refreshToken());
      GoogleSsoIdentityService.ProvisionedIdentity provisionedIdentity =
          googleSsoIdentityService.provisionIdentity(jwt, accessToken);

      return new SsoCallbackResponse(
          accessToken,
          refreshToken,
          provisionedIdentity.profile().getId().toString(),
          provisionedIdentity.linked(),
          "Google SSO login successful");
    } catch (HttpStatusCodeException ex) {
      if (ex.getStatusCode().is4xxClientError()) {
        throw new UnauthorizedException("Invalid SSO callback code");
      }
      throw new IllegalStateException("Identity provider error while processing SSO callback", ex);
    }
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

  private record TokenExchangeRequest(
      @JsonProperty("auth_code") String authCode,
      @JsonProperty("code_verifier") String codeVerifier,
      @JsonProperty("redirect_to") String redirectTo) {
  }

  private record TokenExchangeResponse(
      @JsonProperty("access_token") String accessToken,
      @JsonProperty("refresh_token") String refreshToken) {
  }
}


