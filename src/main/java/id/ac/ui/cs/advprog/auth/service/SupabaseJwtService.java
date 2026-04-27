package id.ac.ui.cs.advprog.auth.service;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class SupabaseJwtService {

  private final String supabaseUrl;
  private final String configuredIssuer;
  private final String expectedAudience;
  private final String configuredJwksUrl;
  private volatile JwtDecoder jwtDecoder;

  public SupabaseJwtService(
      @Value("${supabase.url:}") String supabaseUrl,
      @Value("${supabase.jwt.issuer:}") String configuredIssuer,
      @Value("${supabase.jwt.audience:authenticated}") String expectedAudience,
      @Value("${supabase.jwks-url:}") String configuredJwksUrl) {
    this.supabaseUrl = supabaseUrl;
    this.configuredIssuer = configuredIssuer;
    this.expectedAudience = expectedAudience;
    this.configuredJwksUrl = configuredJwksUrl;
  }

  public Jwt validateAccessToken(String accessToken) {
    try {
      Jwt jwt = getOrCreateDecoder().decode(accessToken);
      validateClaims(jwt);
      return jwt;
    } catch (InvalidTokenException e) {
      throw e;
    } catch (JwtException e) {
      throw new InvalidTokenException("Invalid Supabase access token", e);
    }
  }

  private JwtDecoder getOrCreateDecoder() {
    JwtDecoder currentDecoder = jwtDecoder;
    if (currentDecoder != null) {
      return currentDecoder;
    }

    synchronized (this) {
      if (jwtDecoder == null) {
        jwtDecoder = NimbusJwtDecoder.withJwkSetUri(resolveJwksUrl())
            .jwsAlgorithms(algorithms -> {
              algorithms.add(SignatureAlgorithm.ES256);
              algorithms.add(SignatureAlgorithm.RS256);
              algorithms.add(SignatureAlgorithm.RS512);
            })
            .build();
      }
      return jwtDecoder;
    }
  }

  private void validateClaims(Jwt claims) {
    Instant now = Instant.now();
    Date expirationTime = claims.getExpiresAt() != null ? Date.from(claims.getExpiresAt()) : null;
    if (expirationTime == null || expirationTime.toInstant().isBefore(now)) {
      throw new InvalidTokenException("Token expired");
    }

    String expectedIssuer = resolveIssuer();
    String issuer = claims.getIssuer() != null ? claims.getIssuer().toString() : null;
    if (StringUtils.hasText(expectedIssuer) && !expectedIssuer.equals(issuer)) {
      throw new InvalidTokenException("Token issuer mismatch");
    }

    if (StringUtils.hasText(expectedAudience)) {
      List<String> audiences = claims.getAudience();
      if (audiences == null || !audiences.contains(expectedAudience)) {
        throw new InvalidTokenException("Token audience mismatch");
      }
    }
  }

  private String resolveJwksUrl() {
    if (StringUtils.hasText(configuredJwksUrl)) {
      return configuredJwksUrl;
    }
    if (!StringUtils.hasText(supabaseUrl)) {
      throw new InvalidTokenException("SUPABASE_JWKS_URL or SUPABASE_URL must be configured");
    }
    return trimTrailingSlash(supabaseUrl) + "/auth/v1/.well-known/jwks.json";
  }

  private String resolveIssuer() {
    if (StringUtils.hasText(configuredIssuer)) {
      return configuredIssuer;
    }
    if (!StringUtils.hasText(supabaseUrl)) {
      return "";
    }
    return trimTrailingSlash(supabaseUrl) + "/auth/v1";
  }

  private String trimTrailingSlash(String value) {
    if (value == null || value.isEmpty()) {
      return value;
    }
    if (value.endsWith("/")) {
      return value.substring(0, value.length() - 1);
    }
    return value;
  }

  public static class InvalidTokenException extends JwtException {
    public InvalidTokenException(String message) {
      super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
