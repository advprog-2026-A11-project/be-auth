package id.ac.ui.cs.advprog.auth.service.auth;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoUrlResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class SupabaseGoogleSsoService {

  private final String supabaseUrl;
  private final String redirectUrl;

  public SupabaseGoogleSsoService(
      @Value("${supabase.url:}") String supabaseUrl,
      @Value("${auth.sso.google.redirect-url:}") String redirectUrl) {
    this.supabaseUrl = supabaseUrl;
    this.redirectUrl = redirectUrl;
  }

  public SsoUrlResponse createSsoUrl(String redirectTo) {
    ensureConfig();

    String targetRedirectUrl = redirectUrl;
    if (StringUtils.hasText(redirectTo)) {
      String candidate = redirectTo.trim();
      if (!candidate.startsWith("http://") && !candidate.startsWith("https://")) {
        throw new IllegalArgumentException("redirectTo must start with http:// or https://");
      }
      targetRedirectUrl = candidate;
    }

    String authorizeUrl = UriComponentsBuilder
        .fromHttpUrl(trimTrailingSlash(supabaseUrl) + "/auth/v1/authorize")
        .queryParam("provider", "google")
        .queryParam("redirect_to", targetRedirectUrl)
        .build(false)
        .encode()
        .toUriString();

    return new SsoUrlResponse("google", authorizeUrl, "Google SSO URL generated");
  }

  private void ensureConfig() {
    if (!StringUtils.hasText(supabaseUrl)) {
      throw new IllegalStateException("supabase.url must be configured");
    }
    if (!StringUtils.hasText(redirectUrl)) {
      throw new IllegalStateException("auth.sso.google.redirect-url must be configured");
    }
  }

  private String trimTrailingSlash(String value) {
    if (!StringUtils.hasText(value)) {
      return value;
    }
    return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
  }
}


