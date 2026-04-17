package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.dto.user.DeleteAccountRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UpdateEmailRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UpdatePhoneRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UpdateProfileRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserProfileRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserProfileResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.security.AuthenticatedUserPrincipal;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.AuthSessionService;
import id.ac.ui.cs.advprog.auth.service.RoleMapper;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
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

  private static final String BEARER_PREFIX = "Bearer ";

  private final UserProfileService service;
  private final AuthSessionService authSessionService;
  private final CurrentUserProvider currentUserProvider;

  public UserProfileController(
      UserProfileService service,
      AuthSessionService authSessionService,
      CurrentUserProvider currentUserProvider) {
    this.service = service;
    this.authSessionService = authSessionService;
    this.currentUserProvider = currentUserProvider;
  }

  @PostMapping
  public ResponseEntity<UserProfileResponse> create(@RequestBody UserProfileRequest request) {
    UserProfile user = toEntity(request);
    normalizeIntegrationDefaults(user);
    UserProfile created = service.create(user);
    return new ResponseEntity<>(UserProfileResponse.from(created), HttpStatus.CREATED);
  }

  @GetMapping
  public List<UserProfileResponse> all() {
    return service.findAll().stream().map(UserProfileResponse::from).collect(Collectors.toList());
  }

  @GetMapping("/{id}")
  public ResponseEntity<UserProfileResponse> getById(@PathVariable UUID id) {
    return service.findById(id)
        .map(UserProfileResponse::from)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  @PutMapping("/{id}/displayName")
  public ResponseEntity<Object> updateDisplayName(
      @PathVariable UUID id,
      @RequestBody Map<String, String> body) {
    String name = body.get("displayName");
    if (name == null) {
      Map<String, String> err = new HashMap<>();
      err.put("error", "displayName is required");
      return new ResponseEntity<>(err, HttpStatus.BAD_REQUEST);
    }

    return service.updateDisplayName(id, name)
        .map(UserProfileResponse::from)
        .map(u -> ResponseEntity.ok((Object) u))
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  @PutMapping("/{id}")
  public ResponseEntity<UserProfileResponse> update(
      @PathVariable UUID id,
      @RequestBody UserProfileRequest request) {
    UserProfile user = toEntity(request);
    normalizeIntegrationDefaults(user);
    return service.update(id, user)
        .map(UserProfileResponse::from)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> delete(@PathVariable UUID id) {
    service.deactivateById(id);
    return ResponseEntity.noContent().build();
  }

  @PatchMapping("/{id}/activate")
  public ResponseEntity<UserProfileResponse> activate(@PathVariable UUID id) {
    return ResponseEntity.ok(UserProfileResponse.from(service.activateById(id)));
  }

  @PatchMapping("/me")
  public ResponseEntity<Map<String, String>> updateMe(
      @Valid @RequestBody UpdateProfileRequest request) {
    if ((request.username() == null || request.username().isBlank())
        && (request.displayName() == null || request.displayName().isBlank())) {
      throw new IllegalArgumentException(
          "At least one field must be provided: username or displayName");
    }

    AuthenticatedUserPrincipal principal = currentUserProvider.getCurrentUser()
        .orElseThrow(() -> new IllegalStateException("No authenticated user in security context"));

    UserProfile updated = service.updateCurrentUserProfile(
        principal.sub(),
        principal.email(),
        request.username(),
        request.displayName());

    Map<String, String> response = new HashMap<>();
    response.put("message", "Profile updated");
    response.put("userId", updated.getId().toString());
    response.put("username", updated.getUsername());
    response.put("displayName", updated.getDisplayName());
    response.put("email", updated.getEmail());
    return ResponseEntity.ok(response);
  }

  @PatchMapping("/me/email")
  public ResponseEntity<Map<String, String>> updateEmail(
      @Valid @RequestBody UpdateEmailRequest request,
      HttpServletRequest httpRequest) {
    AuthenticatedUserPrincipal principal = currentUserProvider.getCurrentUser()
        .orElseThrow(() -> new IllegalStateException("No authenticated user in security context"));

    String accessToken = extractBearerToken(httpRequest);
    UserProfile updated = service.updateCurrentUserEmail(
        principal.sub(),
        principal.email(),
        request.email());

    try {
      authSessionService.changeEmail(accessToken, request.email());
    } catch (RuntimeException ex) {
      service.updateCurrentUserEmail(
          principal.sub(),
          updated.getEmail(),
          principal.email());
      throw ex;
    }

    Map<String, String> response = new HashMap<>();
    response.put("message", "Email updated");
    response.put("userId", updated.getId().toString());
    response.put("email", updated.getEmail());
    return ResponseEntity.ok(response);
  }

  @PatchMapping("/me/phone")
  public ResponseEntity<Map<String, String>> updatePhone(
      @Valid @RequestBody UpdatePhoneRequest request) {
    AuthenticatedUserPrincipal principal = currentUserProvider.getCurrentUser()
        .orElseThrow(() -> new IllegalStateException("No authenticated user in security context"));

    UserProfile updated = service.updateCurrentUserPhone(
        principal.sub(),
        principal.email(),
        request.phone());

    Map<String, String> response = new HashMap<>();
    response.put("message", "Phone updated");
    response.put("userId", updated.getId().toString());
    response.put("phone", updated.getPhone());
    return ResponseEntity.ok(response);
  }

  @DeleteMapping("/me")
  public ResponseEntity<Map<String, String>> deleteMe(
      @Valid @RequestBody DeleteAccountRequest request,
      HttpServletRequest httpRequest) {
    if (!"DELETE".equalsIgnoreCase(request.confirmation().trim())) {
      throw new IllegalArgumentException("confirmation must be DELETE");
    }

    AuthenticatedUserPrincipal principal = currentUserProvider.getCurrentUser()
        .orElseThrow(() -> new IllegalStateException("No authenticated user in security context"));

    UserProfile deactivated = service.deactivateCurrentUser(principal.sub(), principal.email());
    authSessionService.logout(extractBearerToken(httpRequest));

    Map<String, String> response = new HashMap<>();
    response.put("message", "Account deleted");
    response.put("userId", deactivated.getId().toString());
    return ResponseEntity.ok(response);
  }

  private void normalizeIntegrationDefaults(UserProfile user) {
    String username = user.getUsername() == null ? "" : user.getUsername().trim();
    user.setUsername(username);

    if (user.getDisplayName() == null) {
      user.setDisplayName("");
    }

    if (user.getRole() == null || user.getRole().isBlank()) {
      user.setRole("STUDENT");
    } else {
      user.setRole(RoleMapper.canonicalize(user.getRole()));
    }

    if (user.getEmail() == null || user.getEmail().isBlank()) {
      user.setEmail(username + "@local.test");
    }
  }

  private UserProfile toEntity(UserProfileRequest request) {
    UserProfile user = new UserProfile();
    user.setUsername(request.getUsername());
    user.setEmail(request.getEmail());
    user.setSupabaseUserId(request.getSupabaseUserId());
    user.setDisplayName(request.getDisplayName());
    user.setRole(request.getRole());
    if (request.getActive() != null) {
      user.setActive(request.getActive());
    }
    return user;
  }

  private String extractBearerToken(HttpServletRequest request) {
    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (!StringUtils.hasText(authHeader) || !authHeader.startsWith(BEARER_PREFIX)) {
      throw new IllegalArgumentException("Missing Bearer token");
    }

    String token = authHeader.substring(BEARER_PREFIX.length()).trim();
    if (!StringUtils.hasText(token)) {
      throw new IllegalArgumentException("Bearer token is empty");
    }
    return token;
  }
}
