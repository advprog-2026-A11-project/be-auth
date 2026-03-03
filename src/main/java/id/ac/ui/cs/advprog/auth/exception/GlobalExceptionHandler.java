package id.ac.ui.cs.advprog.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiErrorResponse> handleValidation(
      MethodArgumentNotValidException ex,
      HttpServletRequest request) {
    Map<String, String> validationErrors = new LinkedHashMap<>();
    for (FieldError error : ex.getBindingResult().getFieldErrors()) {
      validationErrors.put(error.getField(), error.getDefaultMessage());
    }

    ApiErrorResponse body = new ApiErrorResponse(
        Instant.now(),
        HttpStatus.BAD_REQUEST.value(),
        HttpStatus.BAD_REQUEST.getReasonPhrase(),
        "Validation failed",
        request.getRequestURI(),
        validationErrors);

    return ResponseEntity.badRequest().body(body);
  }

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<ApiErrorResponse> handleIllegalArgument(
      IllegalArgumentException ex,
      HttpServletRequest request) {
    HttpStatus status = HttpStatus.BAD_REQUEST;
    ApiErrorResponse body = new ApiErrorResponse(
        Instant.now(),
        status.value(),
        status.getReasonPhrase(),
        ex.getMessage(),
        request.getRequestURI(),
        Map.of());
    return ResponseEntity.status(status).body(body);
  }
}
