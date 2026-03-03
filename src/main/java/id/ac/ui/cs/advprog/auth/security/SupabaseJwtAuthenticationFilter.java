package id.ac.ui.cs.advprog.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

public class SupabaseJwtAuthenticationFilter extends OncePerRequestFilter {

  private static final String BEARER_PREFIX = "Bearer ";

  private final SupabaseJwtService supabaseJwtService;
  private final UserProfileService userProfileService;
  private final ObjectMapper objectMapper;

  public SupabaseJwtAuthenticationFilter(
      SupabaseJwtService supabaseJwtService,
      UserProfileService userProfileService,
      ObjectMapper objectMapper) {
    this.supabaseJwtService = supabaseJwtService;
    this.userProfileService = userProfileService;
    this.objectMapper = objectMapper;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    String method = request.getMethod();

    if (!path.startsWith("/api/")) {
      return true;
    }

    if ("/api/auth/login".equals(path) && HttpMethod.POST.matches(method)) {
      return true;
    }

    if ("/api/auth/sso/google/url".equals(path) && HttpMethod.GET.matches(method)) {
      return true;
    }

    return "/api/auth/sso/google/callback".equals(path) && HttpMethod.POST.matches(method);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

    if (!StringUtils.hasText(authHeader)) {
      filterChain.doFilter(request, response);
      return;
    }

    if (!authHeader.startsWith(BEARER_PREFIX)) {
      writeUnauthorized(response, request, "Authorization header must use Bearer token");
      return;
    }

    String token = authHeader.substring(BEARER_PREFIX.length()).trim();
    if (!StringUtils.hasText(token)) {
      writeUnauthorized(response, request, "Bearer token is empty");
      return;
    }

    try {
      Jwt jwt = supabaseJwtService.validateAccessToken(token);
      String sub = jwt.getSubject();
      String email = jwt.getClaimAsString("email");
      Optional<UserProfile> profile = resolveProfile(sub, email);
      if (profile.isPresent() && !profile.get().isActive()) {
        SecurityContextHolder.clearContext();
        writeUnauthorized(response, request, "Account is inactive");
        return;
      }
      String role = resolveRole(profile, jwt.getClaimAsString("role"));
      List<GrantedAuthority> authorities = buildAuthorities(role);

      AuthenticatedUserPrincipal principal = new AuthenticatedUserPrincipal(sub, email, role);
      UsernamePasswordAuthenticationToken authenticationToken =
          new UsernamePasswordAuthenticationToken(principal, null, authorities);

      SecurityContextHolder.getContext().setAuthentication(authenticationToken);
      filterChain.doFilter(request, response);
    } catch (SupabaseJwtService.InvalidTokenException ex) {
      SecurityContextHolder.clearContext();
      writeUnauthorized(response, request, ex.getMessage());
    }
  }

  private List<GrantedAuthority> buildAuthorities(String role) {
    List<GrantedAuthority> authorities = new ArrayList<>();
    if (StringUtils.hasText(role)) {
      authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
    }
    return authorities;
  }

  private String normalizeRole(String role) {
    if (!StringUtils.hasText(role)) {
      return "";
    }
    String normalized = role.trim().toUpperCase();
    if ("AUTHENTICATED".equals(normalized)) {
      return "USER";
    }
    return normalized;
  }

  private String resolveRole(Optional<UserProfile> profile, String tokenRole) {
    if (profile.isPresent() && StringUtils.hasText(profile.get().getRole())) {
      return normalizeRole(profile.get().getRole());
    }

    return normalizeRole(tokenRole);
  }

  private Optional<UserProfile> resolveProfile(String sub, String email) {
    Optional<UserProfile> profile = Optional.empty();
    if (StringUtils.hasText(sub)) {
      profile = safeOptional(userProfileService.findBySupabaseUserId(sub));
    }
    if (profile.isEmpty() && StringUtils.hasText(email)) {
      profile = safeOptional(userProfileService.findByEmail(email));
    }
    return profile;
  }

  private Optional<UserProfile> safeOptional(Optional<UserProfile> value) {
    return value == null ? Optional.empty() : value;
  }

  private void writeUnauthorized(
      HttpServletResponse response,
      HttpServletRequest request,
      String message) throws IOException {
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    Map<String, Object> payload = new HashMap<>();
    payload.put("timestamp", Instant.now().toString());
    payload.put("status", HttpStatus.UNAUTHORIZED.value());
    payload.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());
    payload.put("message", message);
    payload.put("path", request.getRequestURI());

    response.getWriter().write(objectMapper.writeValueAsString(payload));
  }
}
