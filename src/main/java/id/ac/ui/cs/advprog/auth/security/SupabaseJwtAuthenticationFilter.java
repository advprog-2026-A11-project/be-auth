package id.ac.ui.cs.advprog.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.RoleMapper;
import id.ac.ui.cs.advprog.auth.service.TokenRevocationService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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

  private final TokenRevocationService tokenRevocationService;
  private final UserProfileService userProfileService;
  private final ObjectMapper objectMapper;

  public SupabaseJwtAuthenticationFilter(
      TokenRevocationService tokenRevocationService,
      UserProfileService userProfileService,
      ObjectMapper objectMapper) {
    this.tokenRevocationService = tokenRevocationService;
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

    if ("/api/auth/register".equals(path) && HttpMethod.POST.matches(method)) {
      return true;
    }

    if ("/api/auth/refresh".equals(path) && HttpMethod.POST.matches(method)) {
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

    Optional<Jwt> currentJwt = SecurityContextJwtAccessor.getCurrentJwt();
    if (currentJwt.isEmpty()) {
      filterChain.doFilter(request, response);
      return;
    }

    Jwt jwt = currentJwt.get();
    String sub = jwt.getSubject();
    String email = jwt.getClaimAsString("email");
    Optional<UserProfile> profile = resolveProfile(sub, email);
    if (profile.isPresent() && !profile.get().isActive()) {
      SecurityContextHolder.clearContext();
      UnauthorizedResponseWriter.write(
          objectMapper,
          request,
          response,
          DEACTIVATED_ACCOUNT_MESSAGE);
      return;
    }

    String role = resolveRole(profile, jwt.getClaimAsString("role"));
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
    if (profile.isPresent() && StringUtils.hasText(profile.get().getRole())) {
      return RoleMapper.canonicalize(profile.get().getRole());
    }

    return RoleMapper.canonicalize(tokenRole);
  }

  private Optional<UserProfile> resolveProfile(String sub, String email) {
    Optional<UserProfile> profile = Optional.empty();
    if (StringUtils.hasText(sub)) {
      profile = userProfileService.findBySupabaseUserId(sub);
    }
    if (profile.isEmpty() && StringUtils.hasText(email)) {
      profile = userProfileService.findByEmail(email);
    }
    return profile;
  }
}
