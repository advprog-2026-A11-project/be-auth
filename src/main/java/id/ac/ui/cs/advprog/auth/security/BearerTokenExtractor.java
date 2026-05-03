package id.ac.ui.cs.advprog.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

public final class BearerTokenExtractor {

  private static final String BEARER_PREFIX = "Bearer ";

  private BearerTokenExtractor() {
  }

  public static String extractOrUnauthorized(HttpServletRequest request) {
    try {
      return extract(request);
    } catch (IllegalArgumentException ex) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }
  }

  public static String extractOrBadRequest(HttpServletRequest request) {
    return extract(request);
  }

  private static String extract(HttpServletRequest request) {
    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (!StringUtils.hasText(authHeader) || !authHeader.startsWith(BEARER_PREFIX)) {
      throw new IllegalArgumentException("Missing Bearer token");
    }

    String token = authHeader.substring(BEARER_PREFIX.length()).trim();
    if (!StringUtils.hasText(token)) {
      throw new IllegalArgumentException("Bearer token is empty");
    }

    return token;
  }
}

