package id.ac.ui.cs.advprog.auth.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
  public ResponseEntity<Object> updateDisplayName(@PathVariable Long id, @RequestBody Map<String, String> body) {
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
