package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.AdminPingResponse;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import java.util.UUID;
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
  public ResponseEntity<AdminPingResponse> ping() {
    var principal = currentUserProvider.requireCurrentUser();
    return ResponseEntity.ok(new AdminPingResponse(
        "Admin access granted",
        UUID.fromString(principal.publicUserId())));
  }
}

