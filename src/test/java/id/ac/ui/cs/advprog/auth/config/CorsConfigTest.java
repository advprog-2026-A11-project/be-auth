package id.ac.ui.cs.advprog.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

class CorsConfigTest {

  private final CorsConfig corsConfig = new CorsConfig();

  @Test
  void corsConfigurerParsesCommaSeparatedOrigins() {
    WebMvcConfigurer configurer =
        corsConfig.corsConfigurer("http://localhost:3000,fe-yomu.vercel.app");

    ExposedCorsRegistry registry = new ExposedCorsRegistry();
    configurer.addCorsMappings(registry);

    CorsConfiguration config = registry.configs().get("/api/**");
    assertNotNull(config);

    List<String> allowedOriginPatterns = config.getAllowedOriginPatterns();
    assertNotNull(allowedOriginPatterns);
    assertEquals(2, allowedOriginPatterns.size());
    assertTrue(allowedOriginPatterns.contains("http://localhost:3000"));
    assertTrue(allowedOriginPatterns.contains("https://fe-yomu.vercel.app"));
  }

  @Test
  void corsConfigurerFallsBackToLocalhostWhenEmpty() {
    WebMvcConfigurer configurer = corsConfig.corsConfigurer("   ,   ");

    ExposedCorsRegistry registry = new ExposedCorsRegistry();
    configurer.addCorsMappings(registry);

    CorsConfiguration config = registry.configs().get("/api/**");
    assertNotNull(config);
    assertEquals(List.of("http://localhost:3000"), config.getAllowedOriginPatterns());
  }

  @Test
  void corsConfigurerNormalizesBareLocalOrigins() {
    WebMvcConfigurer configurer =
        corsConfig.corsConfigurer("localhost:3000,127.0.0.1:4173");

    ExposedCorsRegistry registry = new ExposedCorsRegistry();
    configurer.addCorsMappings(registry);

    CorsConfiguration config = registry.configs().get("/api/**");
    assertNotNull(config);
    assertEquals(
        List.of("http://localhost:3000", "http://127.0.0.1:4173"),
        config.getAllowedOriginPatterns());
  }

  private static class ExposedCorsRegistry extends CorsRegistry {
    Map<String, CorsConfiguration> configs() {
      return getCorsConfigurations();
    }
  }
}
