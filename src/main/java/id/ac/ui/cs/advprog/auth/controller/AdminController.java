package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

  private final CurrentUserProvider currentUserProvider;

  public AdminController(CurrentUserProvider currentUserProvider) {
    this.currentUserProvider = currentUserProvider;
  }

  @GetMapping("/ping")
  public ResponseEntity<Map<String, String>> ping() {
    String userId = currentUserProvider.requireCurrentUserId();
    Map<String, String> response = new HashMap<>();
    response.put("message", "Admin access granted");
    response.put("userId", userId);
    return ResponseEntity.ok(response);
  }
}
