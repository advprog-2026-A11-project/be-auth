package id.ac.ui.cs.advprog.auth.functional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ActuatorHealthFunctionalTest {

  @Autowired
  private TestRestTemplate restTemplate;

  @Test
  void actuatorHealthWhenApplicationStartsReturnsUp() {
    // Arrange

    // Act
    ResponseEntity<Map> response = restTemplate.getForEntity("/actuator/health", Map.class);

    // Assert
    assertEquals(HttpStatus.OK, response.getStatusCode());
    assertNotNull(response.getBody());
    assertEquals("UP", response.getBody().get("status"));
  }
}
