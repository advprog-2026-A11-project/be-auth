package id.ac.ui.cs.advprog.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.auth.security.SupabaseJwtAuthenticationFilter;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.TokenRevocationService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

  @Bean
  public SupabaseJwtAuthenticationFilter supabaseJwtAuthenticationFilter(
      TokenRevocationService tokenRevocationService,
      UserProfileService userProfileService,
      ObjectMapper objectMapper) {
    return new SupabaseJwtAuthenticationFilter(
        tokenRevocationService,
        userProfileService,
        objectMapper);
  }

  @Bean
  public JwtDecoder jwtDecoder(SupabaseJwtService supabaseJwtService) {
    return token -> {
      try {
        return supabaseJwtService.validateAccessToken(token);
      } catch (SupabaseJwtService.InvalidTokenException ex) {
        throw new BadJwtException(ex.getMessage(), ex);
      }
    };
  }

  @Bean
  public AuthenticationEntryPoint authenticationEntryPoint(ObjectMapper objectMapper) {
    return (request, response, authException) ->
        writeUnauthorized(objectMapper, request, response, authException);
  }

  @Bean
  @SuppressWarnings("java:S4502")
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      SupabaseJwtAuthenticationFilter supabaseJwtAuthenticationFilter,
      AuthenticationEntryPoint authenticationEntryPoint) throws Exception {
    http
        // This service uses stateless Bearer tokens for /api/** endpoints.
        // NOSONAR
        .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**", "/actuator/**"))
        .cors(Customizer.withDefaults())
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/refresh").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/auth/sso/google/url").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/sso/google/callback").permitAll()
            .requestMatchers("/actuator/health", "/actuator/info").permitAll()
            .requestMatchers("/", "/index.html", "/error", "/favicon.ico").permitAll()
            .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
            .requestMatchers(HttpMethod.PATCH, "/api/users/me").authenticated()
            .requestMatchers(HttpMethod.PATCH, "/api/users/me/email").authenticated()
            .requestMatchers(HttpMethod.PATCH, "/api/users/me/phone").authenticated()
            .requestMatchers(HttpMethod.DELETE, "/api/users/me").authenticated()
            .requestMatchers("/api/users/**").hasRole("ADMIN")
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .requestMatchers("/api/**").authenticated()
            .anyRequest().permitAll())
        .exceptionHandling(exceptions ->
            exceptions.authenticationEntryPoint(authenticationEntryPoint))
        .oauth2ResourceServer(oauth2 -> oauth2
            .authenticationEntryPoint(authenticationEntryPoint)
            .jwt(Customizer.withDefaults()))
        .addFilterAfter(
            supabaseJwtAuthenticationFilter,
            BearerTokenAuthenticationFilter.class);

    return http.build();
  }

  private void writeUnauthorized(
      ObjectMapper objectMapper,
      HttpServletRequest request,
      jakarta.servlet.http.HttpServletResponse response,
      AuthenticationException authException) throws IOException {
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("timestamp", Instant.now().toString());
    payload.put("status", HttpStatus.UNAUTHORIZED.value());
    payload.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());
    payload.put("message", authException.getMessage());
    payload.put("path", request.getRequestURI());

    response.getWriter().write(objectMapper.writeValueAsString(payload));
  }
}
