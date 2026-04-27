package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthMeResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.ChangePasswordRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.LoginRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.LogoutResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.MessageResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.RefreshTokenRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.RegisterRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.security.AuthenticatedUserPrincipal;
import id.ac.ui.cs.advprog.auth.security.BearerTokenExtractor;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.AuthLoginService;
import id.ac.ui.cs.advprog.auth.service.AuthSessionService;
import id.ac.ui.cs.advprog.auth.service.GoogleSsoService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private static final String EMAIL_CLAIM = "email";

  private final AuthLoginService authLoginService;
  private final AuthSessionService authSessionService;
  private final GoogleSsoService googleSsoService;
  private final UserProfileService userProfileService;
  private final CurrentUserProvider currentUserProvider;
  private final boolean passwordAuthEnabled;

  public AuthController(
      AuthLoginService authLoginService,
      AuthSessionService authSessionService,
      GoogleSsoService googleSsoService,
      UserProfileService userProfileService,
      CurrentUserProvider currentUserProvider,
      @Value("${auth.password.enabled:true}") boolean passwordAuthEnabled) {
    this.authLoginService = authLoginService;
    this.authSessionService = authSessionService;
    this.googleSsoService = googleSsoService;
    this.userProfileService = userProfileService;
    this.currentUserProvider = currentUserProvider;
    this.passwordAuthEnabled = passwordAuthEnabled;
  }

  @GetMapping("/me")
  public ResponseEntity<?> me(HttpServletRequest request) {
    Optional<Jwt> currentJwt = resolveCurrentJwt();
    if (currentJwt.isEmpty()) {
      return unauthorized("Missing Bearer token");
    }

    Jwt claims = currentJwt.get();
    String sub = claims.getSubject();
    String email = claims.getClaimAsString(EMAIL_CLAIM);

    Optional<UserProfile> profile = resolveProfileSafely(sub, email);
    return ResponseEntity.ok(AuthMeResponse.of(
        sub,
        claims.getAudience(),
        claims.getIssuer(),
        claims.getExpiresAt(),
        profile.orElse(null)));
  }

  @PostMapping("/login")
  public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
    ensurePasswordAuthEnabled();
    LoginResponse response = authLoginService.login(request.identifier(), request.password());
    return ResponseEntity.ok(response);
  }

  @PostMapping("/register")
  public ResponseEntity<LoginResponse> register(@Valid @RequestBody RegisterRequest request) {
    ensurePasswordAuthEnabled();
    LoginResponse response = authLoginService.register(
        request.email(),
        request.password(),
        request.username(),
        request.displayName());
    return ResponseEntity.status(HttpStatus.CREATED).body(response);
  }

  @PostMapping("/refresh")
  public ResponseEntity<LoginResponse> refresh(
      @Valid @RequestBody RefreshTokenRequest request) {
    LoginResponse response = authSessionService.refresh(request.refreshToken());
    return ResponseEntity.ok(response);
  }

  @PostMapping("/logout")
  public ResponseEntity<LogoutResponse> logout(HttpServletRequest request) {
    authSessionService.logout(BearerTokenExtractor.extractOrUnauthorized(request));
    return ResponseEntity.ok(new LogoutResponse("Logout successful"));
  }

  @PostMapping("/change-password")
  public ResponseEntity<MessageResponse> changePassword(
      @Valid @RequestBody ChangePasswordRequest request,
      HttpServletRequest httpRequest) {
    AuthenticatedUserPrincipal principal = currentUserProvider.getCurrentUser()
        .orElseThrow(() -> new ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            "No authenticated user in security context"));

    authSessionService.changePassword(
        BearerTokenExtractor.extractOrUnauthorized(httpRequest),
        principal.email(),
        request.currentPassword(),
        request.newPassword());

    return ResponseEntity.ok(new MessageResponse("Password changed"));
  }

  @GetMapping("/sso/google/url")
  public ResponseEntity<SsoUrlResponse> googleSsoUrl(
      @RequestParam(value = "redirectTo", required = false) String redirectTo) {
    if (!StringUtils.hasText(redirectTo)) {
      return ResponseEntity.ok(googleSsoService.createSsoUrl());
    }
    return ResponseEntity.ok(googleSsoService.createSsoUrl(redirectTo));
  }

  @PostMapping("/sso/google/callback")
  public ResponseEntity<SsoCallbackResponse> googleSsoCallback(
      @Valid @RequestBody SsoCallbackRequest request) {
    return ResponseEntity.ok(googleSsoService.handleCallback(request));
  }

  private ResponseEntity<Map<String, Object>> unauthorized(String message) {
    Map<String, Object> response = new HashMap<>();
    response.put("error", message);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
  }

  private Optional<UserProfile> resolveProfileSafely(String sub, String email) {
    try {
      Optional<UserProfile> profile = Optional.empty();
      if (StringUtils.hasText(sub)) {
        profile = userProfileService.findBySupabaseUserId(sub);
      }
      if (profile.isEmpty() && StringUtils.hasText(email)) {
        profile = userProfileService.findByEmail(email);
      }
      return profile;
    } catch (DataAccessException ex) {
      return Optional.empty();
    }
  }

  private Optional<Jwt> resolveCurrentJwt() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null) {
      return Optional.empty();
    }

    if (authentication.getPrincipal() instanceof Jwt jwt) {
      return Optional.of(jwt);
    }

    if (authentication.getCredentials() instanceof Jwt jwt) {
      return Optional.of(jwt);
    }

    return Optional.empty();
  }

  private void ensurePasswordAuthEnabled() {
    if (!passwordAuthEnabled) {
      throw new ResponseStatusException(
          HttpStatus.FORBIDDEN,
          "Password auth is disabled. Use Google SSO.");
    }
  }
}
