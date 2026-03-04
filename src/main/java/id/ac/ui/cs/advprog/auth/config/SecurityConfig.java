package id.ac.ui.cs.advprog.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.auth.security.SupabaseJwtAuthenticationFilter;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

  @Bean
  public SupabaseJwtAuthenticationFilter supabaseJwtAuthenticationFilter(
      SupabaseJwtService supabaseJwtService,
      UserProfileService userProfileService,
      ObjectMapper objectMapper) {
    return new SupabaseJwtAuthenticationFilter(
        supabaseJwtService,
        userProfileService,
        objectMapper);
  }

  @Bean
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      SupabaseJwtAuthenticationFilter supabaseJwtAuthenticationFilter,
      ObjectMapper objectMapper) throws Exception {
    http
        // This service uses stateless Bearer tokens for /api/** endpoints.
        .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**", "/actuator/**"))
        .cors(Customizer.withDefaults())
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
            .requestMatchers(HttpMethod.GET, "/api/auth/sso/google/url").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/auth/sso/google/callback").permitAll()
            .requestMatchers("/actuator/health", "/actuator/info").permitAll()
            .requestMatchers("/", "/index.html", "/error", "/favicon.ico").permitAll()
            .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
            .requestMatchers(HttpMethod.DELETE, "/api/users/me").authenticated()
            .requestMatchers(HttpMethod.PUT, "/api/users/*").hasRole("ADMIN")
            .requestMatchers(HttpMethod.DELETE, "/api/users/*").hasRole("ADMIN")
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .requestMatchers("/api/**").authenticated()
            .anyRequest().permitAll())
        .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, authException) ->
            writeUnauthorized(response, request, objectMapper, "Unauthorized")))
        .addFilterBefore(
            supabaseJwtAuthenticationFilter,
            UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  private void writeUnauthorized(
      HttpServletResponse response,
      HttpServletRequest request,
      ObjectMapper objectMapper,
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
