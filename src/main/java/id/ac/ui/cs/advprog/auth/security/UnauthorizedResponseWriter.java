package id.ac.ui.cs.advprog.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

public final class UnauthorizedResponseWriter {

  private UnauthorizedResponseWriter() {
  }

  public static void write(
      ObjectMapper objectMapper,
      HttpServletRequest request,
      HttpServletResponse response,
      String message) throws IOException {
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    UnauthorizedPayload payload = new UnauthorizedPayload(
        Instant.now().toString(),
        HttpStatus.UNAUTHORIZED.value(),
        HttpStatus.UNAUTHORIZED.getReasonPhrase(),
        message,
        request.getRequestURI());
    response.getWriter().write(objectMapper.writeValueAsString(payload));
  }

  private record UnauthorizedPayload(
      String timestamp,
      int status,
      String error,
      String message,
      String path) {
  }
}

