package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.dto.user.UserRequests.DeleteAccountRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserRequests.UpdateEmailRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserRequests.UpdatePhoneRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserRequests.UpdateProfileRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserProfileRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserProfileResponse;
import id.ac.ui.cs.advprog.auth.dto.user.UserResponses.DeleteAccountResponse;
import id.ac.ui.cs.advprog.auth.dto.user.UserResponses.UpdateEmailResponse;
import id.ac.ui.cs.advprog.auth.dto.user.UserResponses.UpdatePhoneResponse;
import id.ac.ui.cs.advprog.auth.dto.user.UserResponses.UpdateProfileResponse;
import id.ac.ui.cs.advprog.auth.model.Role;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.security.AuthenticatedUserPrincipal;
import id.ac.ui.cs.advprog.auth.security.BearerTokenExtractor;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.auth.AuthSessionService;
import id.ac.ui.cs.advprog.auth.service.identity.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
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
  public ResponseEntity<UpdateProfileResponse> updateMe(
      @Valid @RequestBody UpdateProfileRequest request) {
    if ((request.username() == null || request.username().isBlank())
        && (request.displayName() == null || request.displayName().isBlank())) {
      throw new IllegalArgumentException(
          "At least one field must be provided: username or displayName");
    }

    AuthenticatedUserPrincipal principal = currentUserProvider.requireCurrentUser();

    UserProfile updated = service.updateCurrentUserProfile(
        principal.publicUserId(),
        request.username(),
        request.displayName());

    return ResponseEntity.ok(new UpdateProfileResponse(
        "Profile updated",
        updated.getId(),
        updated.getUsername(),
        updated.getDisplayName(),
        updated.getEmail()));
  }

  @PatchMapping("/me/email")
  public ResponseEntity<UpdateEmailResponse> updateEmail(
      @Valid @RequestBody UpdateEmailRequest request,
      HttpServletRequest httpRequest) {
    AuthenticatedUserPrincipal principal = currentUserProvider.requireCurrentUser();

    String accessToken = BearerTokenExtractor.extractOrBadRequest(httpRequest);
    UserProfile updated = authSessionService.changeEmail(
        accessToken,
        principal.publicUserId(),
        principal.email(),
        request.email());

    return ResponseEntity.ok(new UpdateEmailResponse(
        "Email updated",
        updated.getId(),
        updated.getEmail()));
  }

  @PatchMapping("/me/phone")
  public ResponseEntity<UpdatePhoneResponse> updatePhone(
      @Valid @RequestBody UpdatePhoneRequest request) {
    AuthenticatedUserPrincipal principal = currentUserProvider.requireCurrentUser();

    UserProfile updated = service.updateCurrentUserPhone(
        principal.publicUserId(),
        request.phone());

    return ResponseEntity.ok(new UpdatePhoneResponse(
        "Phone updated",
        updated.getId(),
        updated.getPhone()));
  }

  @DeleteMapping("/me")
  public ResponseEntity<DeleteAccountResponse> deleteMe(
      @Valid @RequestBody DeleteAccountRequest request,
      HttpServletRequest httpRequest) {
    if (!"DELETE".equalsIgnoreCase(request.confirmation().trim())) {
      throw new IllegalArgumentException("confirmation must be DELETE");
    }

    AuthenticatedUserPrincipal principal = currentUserProvider.requireCurrentUser();

    UserProfile deactivated = service.deactivateCurrentUser(principal.publicUserId());
    authSessionService.logout(BearerTokenExtractor.extractOrBadRequest(httpRequest));

    return ResponseEntity.ok(new DeleteAccountResponse(
        "Account deleted",
        deactivated.getId()));
  }

  private void normalizeIntegrationDefaults(UserProfile user) {
    String username = user.getUsername() == null ? "" : user.getUsername().trim();
    user.setUsername(username);

    if (user.getDisplayName() == null) {
      user.setDisplayName("");
    }

    user.setRole(Role.canonicalize(user.getRole()));

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
}

