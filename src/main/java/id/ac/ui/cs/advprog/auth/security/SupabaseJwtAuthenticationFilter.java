package id.ac.ui.cs.advprog.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.auth.exception.ApiErrorResponse;
import id.ac.ui.cs.advprog.auth.model.Role;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import id.ac.ui.cs.advprog.auth.service.state.TokenRevocationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
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
  private static final String DEACTIVATED_ACCOUNT_MESSAGE =
      "Your account has been deactivated. Please contact an administrator.";
  private static final String MISSING_PUBLIC_USER_ID_MESSAGE =
      "Missing public user id claim";

  private final TokenRevocationService tokenRevocationService;
  private final UserProfileService userProfileService;
  private final CurrentUserProvider currentUserProvider;
  private final ObjectMapper objectMapper;

  public SupabaseJwtAuthenticationFilter(
      TokenRevocationService tokenRevocationService,
      UserProfileService userProfileService,
      CurrentUserProvider currentUserProvider,
      ObjectMapper objectMapper) {
    this.tokenRevocationService = tokenRevocationService;
    this.userProfileService = userProfileService;
    this.currentUserProvider = currentUserProvider;
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

    if ("/api/auth/register".equals(path) && HttpMethod.POST.matches(method)) {
      return true;
    }

    if ("/api/auth/refresh".equals(path) && HttpMethod.POST.matches(method)) {
      return true;
    }

    return "/api/auth/sso/google/url".equals(path) && HttpMethod.GET.matches(method);
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
      UnauthorizedResponseWriter.write(
          objectMapper,
          request,
          response,
          "Authorization header must use Bearer token");
      return;
    }

    String token = authHeader.substring(BEARER_PREFIX.length()).trim();
    if (!StringUtils.hasText(token)) {
      UnauthorizedResponseWriter.write(
          objectMapper,
          request,
          response,
          "Bearer token is empty");
      return;
    }

    if (tokenRevocationService.isRevoked(token)) {
      SecurityContextHolder.clearContext();
      UnauthorizedResponseWriter.write(objectMapper, request, response, "Session has been revoked");
      return;
    }

    Optional<Jwt> currentJwt = currentUserProvider.getCurrentJwt();
    if (currentJwt.isEmpty()) {
      filterChain.doFilter(request, response);
      return;
    }

    Jwt jwt = currentJwt.get();
    Optional<UserProfile> profile;
    try {
      String publicUserId = currentUserProvider.requireCurrentPublicUserId();
      profile = userProfileService.findByPublicUserId(publicUserId);
    } catch (id.ac.ui.cs.advprog.auth.exception.UnauthorizedException ex) {
      SecurityContextHolder.clearContext();
      UnauthorizedResponseWriter.write(
          objectMapper,
          request,
          response,
          MISSING_PUBLIC_USER_ID_MESSAGE);
      return;
    } catch (DataAccessException ex) {
      writeServiceUnavailable(request, response);
      return;
    }
    if (profile.isPresent() && !profile.get().isActive()) {
      SecurityContextHolder.clearContext();
      UnauthorizedResponseWriter.write(
          objectMapper,
          request,
          response,
          DEACTIVATED_ACCOUNT_MESSAGE);
      return;
    }

    String role = resolveRole(profile, jwt.getClaimAsString("user_role"));
    List<GrantedAuthority> authorities = buildAuthorities(role);
    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(jwt, token, authorities);

    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    filterChain.doFilter(request, response);
  }

  private List<GrantedAuthority> buildAuthorities(String role) {
    List<GrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
    return authorities;
  }

  private String resolveRole(Optional<UserProfile> profile, String tokenRole) {
    if (profile.isPresent()) {
      return Role.canonicalize(profile.get().getRole());
    }

    return Role.canonicalize(tokenRole);
  }

  private void writeServiceUnavailable(
      HttpServletRequest request,
      HttpServletResponse response) throws IOException {
    response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    ApiErrorResponse payload = new ApiErrorResponse(
        Instant.now(),
        HttpStatus.SERVICE_UNAVAILABLE.value(),
        HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase(),
        "Database unavailable. Check Supabase DB host/connection.",
        request.getRequestURI(),
        Map.of());
    response.getWriter().write(objectMapper.writeValueAsString(payload));
  }

}

