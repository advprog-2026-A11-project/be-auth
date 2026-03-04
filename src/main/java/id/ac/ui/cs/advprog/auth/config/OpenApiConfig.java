package id.ac.ui.cs.advprog.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

  @Bean
  public OpenAPI authOpenApi() {
    final String bearerSchemeName = "bearerAuth";

    return new OpenAPI()
        .info(new Info()
            .title("YOMU Auth API")
            .description("Authentication, profile, and admin endpoints for YOMU backend")
            .version("v1"))
        .addSecurityItem(new SecurityRequirement().addList(bearerSchemeName))
        .components(new Components()
            .addSecuritySchemes(
                bearerSchemeName,
                new SecurityScheme()
                    .name(bearerSchemeName)
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")));
  }
}
