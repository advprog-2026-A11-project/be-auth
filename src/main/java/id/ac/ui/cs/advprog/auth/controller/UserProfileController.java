package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.dto.user.DeleteAccountRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UpdateProfileRequest;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserProfileController {

  private final UserProfileService service;

  @Autowired
  public UserProfileController(UserProfileService service) {
    this.service = service;
  }

  @PostMapping
  public ResponseEntity<UserProfile> create(@RequestBody UserProfile user) {
    normalizeIntegrationDefaults(user);
    UserProfile created = service.create(user);
    return new ResponseEntity<>(created, HttpStatus.CREATED);
  }

  @GetMapping
  public List<UserProfile> all() {
    return service.findAll();
  }

  @GetMapping("/{id}")
  public ResponseEntity<UserProfile> getById(@PathVariable Long id) {
    return service.findById(id)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  @PutMapping("/{id}/displayName")
  public ResponseEntity<Object> updateDisplayName(
      @PathVariable Long id,
      @RequestBody Map<String, String> body) {
    String name = body.get("displayName");
    if (name == null) {
      Map<String, String> err = new HashMap<>();
      err.put("error", "displayName is required");
      return new ResponseEntity<>(err, HttpStatus.BAD_REQUEST);
    }

    return service.updateDisplayName(id, name)
        .map(u -> ResponseEntity.ok((Object) u))
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  @PutMapping("/{id}")
  public ResponseEntity<UserProfile> update(@PathVariable Long id, @RequestBody UserProfile user) {
    normalizeIntegrationDefaults(user);
    return service.update(id, user)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> delete(@PathVariable Long id) {
    service.deleteById(id);
    return ResponseEntity.noContent().build();
  }

  @PatchMapping("/me")
  public ResponseEntity<Map<String, String>> updateMe(@Valid @RequestBody UpdateProfileRequest request) {
    if ((request.username() == null || request.username().isBlank())
        && (request.displayName() == null || request.displayName().isBlank())) {
      throw new IllegalArgumentException("At least one field must be provided: username or displayName");
    }

    Map<String, String> response = new HashMap<>();
    response.put("message", "Profile update contract is ready. Implementation follows in next step.");
    return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(response);
  }

  @DeleteMapping("/me")
  public ResponseEntity<Map<String, String>> deleteMe(@Valid @RequestBody DeleteAccountRequest request) {
    if (!"DELETE".equalsIgnoreCase(request.confirmation().trim())) {
      throw new IllegalArgumentException("confirmation must be DELETE");
    }

    Map<String, String> response = new HashMap<>();
    response.put("message", "Delete account contract is ready. Implementation follows in next step.");
    return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(response);
  }

  private void normalizeIntegrationDefaults(UserProfile user) {
    String username = user.getUsername() == null ? "" : user.getUsername().trim();
    user.setUsername(username);

    if (user.getDisplayName() == null) {
      user.setDisplayName("");
    }

    if (user.getRole() == null || user.getRole().isBlank()) {
      user.setRole("USER");
    }

    if (user.getEmail() == null || user.getEmail().isBlank()) {
      user.setEmail(username + "@local.test");
    }
  }
}
