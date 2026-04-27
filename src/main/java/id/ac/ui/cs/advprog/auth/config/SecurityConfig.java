package id.ac.ui.cs.advprog.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.security.SupabaseJwtAuthenticationFilter;
import id.ac.ui.cs.advprog.auth.security.UnauthorizedResponseWriter;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.TokenRevocationService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
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
      CurrentUserProvider currentUserProvider,
      ObjectMapper objectMapper) {
    return new SupabaseJwtAuthenticationFilter(
        tokenRevocationService,
        userProfileService,
        currentUserProvider,
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
    return (request, response, authException) -> UnauthorizedResponseWriter.write(
        objectMapper,
        request,
        response,
        authException.getMessage());
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
}
