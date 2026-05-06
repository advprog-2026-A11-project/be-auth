package id.ac.ui.cs.advprog.auth.config;

import java.util.Arrays;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig {

  @Bean
  public WebMvcConfigurer corsConfigurer(
      @Value("${FRONTEND_URL:http://localhost:3000}") String frontendUrl) {
    final String[] allowedOrigins = resolveAllowedOrigins(frontendUrl);

    return new WebMvcConfigurer() {
      @Override
      public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOriginPatterns(allowedOrigins)
            .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
            .allowedHeaders("*");
      }
    };
  }

  private String normalizeOriginPattern(String origin) {
    if (origin.contains("://")) {
      return origin;
    }
    if (origin.startsWith("localhost") || origin.startsWith("127.0.0.1")) {
      return "http://" + origin;
    }
    return "https://" + origin;
  }

  private String[] resolveAllowedOrigins(String frontendUrl) {
    String[] allowedOrigins = Arrays.stream(frontendUrl.split(","))
        .map(String::trim)
        .filter(StringUtils::hasText)
        .map(this::normalizeOriginPattern)
        .toArray(String[]::new);
    if (allowedOrigins.length == 0) {
      return new String[] {"http://localhost:3000"};
    }
    return allowedOrigins;
  }
}

