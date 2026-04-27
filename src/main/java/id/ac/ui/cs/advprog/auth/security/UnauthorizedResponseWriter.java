package id.ac.ui.cs.advprog.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
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

    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("timestamp", Instant.now().toString());
    payload.put("status", HttpStatus.UNAUTHORIZED.value());
    payload.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());
    payload.put("message", message);
    payload.put("path", request.getRequestURI());

    response.getWriter().write(objectMapper.writeValueAsString(payload));
  }
}
