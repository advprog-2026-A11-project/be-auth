package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.AdminPingResponse;
import id.ac.ui.cs.advprog.auth.exception.UnauthorizedException;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

  private final CurrentUserProvider currentUserProvider;
  private final UserProfileService userProfileService;

  public AdminController(
      CurrentUserProvider currentUserProvider,
      UserProfileService userProfileService) {
    this.currentUserProvider = currentUserProvider;
    this.userProfileService = userProfileService;
  }

  @GetMapping("/ping")
  public ResponseEntity<AdminPingResponse> ping() {
    var currentUser = currentUserProvider.requireCurrentUser();
    var profile = userProfileService.findBySupabaseUserId(currentUser.sub())
        .orElseThrow(() -> new UnauthorizedException("Authenticated user profile not found"));
    return ResponseEntity.ok(new AdminPingResponse("Admin access granted", profile.getId()));
  }
}
