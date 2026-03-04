package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.RegisterRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.AuthLoginService;
import id.ac.ui.cs.advprog.auth.service.GoogleSsoService;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
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
  private final GoogleSsoService googleSsoService;
  private final SupabaseJwtService supabaseJwtService;
  private final UserProfileService userProfileService;
  private final boolean passwordAuthEnabled;

  public AuthController(
      AuthLoginService authLoginService,
      GoogleSsoService googleSsoService,
      SupabaseJwtService supabaseJwtService,
      UserProfileService userProfileService,
      @Value("${auth.password.enabled:true}") boolean passwordAuthEnabled) {
    this.authLoginService = authLoginService;
    this.googleSsoService = googleSsoService;
    this.supabaseJwtService = supabaseJwtService;
    this.userProfileService = userProfileService;
    this.passwordAuthEnabled = passwordAuthEnabled;
  }

  @GetMapping("/me")
  public ResponseEntity<Map<String, Object>> me(HttpServletRequest request) {
    String authHeader = request.getHeader("Authorization");
    if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
      return unauthorized("Missing Bearer token");
    }

    String token = authHeader.substring(7);
    try {
      Jwt claims = supabaseJwtService.validateAccessToken(token);
      String sub = claims.getSubject();
      String email = claims.getClaimAsString(EMAIL_CLAIM);

      Map<String, Object> payload = new HashMap<>();
      payload.put("sub", sub);
      payload.put(EMAIL_CLAIM, email);
      payload.put("role", claims.getClaimAsString("role"));
      payload.put("aud", claims.getAudience());
      payload.put("iss", claims.getIssuer());
      payload.put("exp", claims.getExpiresAt());

      Optional<UserProfile> profile = resolveProfileSafely(sub, email);

      if (profile.isPresent()) {
        UserProfile user = profile.get();
        Map<String, Object> profilePayload = new HashMap<>();
        profilePayload.put("id", user.getId());
        profilePayload.put("supabaseUserId", user.getSupabaseUserId());
        profilePayload.put("username", user.getUsername());
        profilePayload.put(EMAIL_CLAIM, user.getEmail());
        profilePayload.put("displayName", user.getDisplayName());
        profilePayload.put("role", user.getRole());
        profilePayload.put("isActive", user.isActive());
        payload.put("profile", profilePayload);
      } else {
        payload.put("profile", null);
      }

      return ResponseEntity.ok(payload);
    } catch (SupabaseJwtService.InvalidTokenException ex) {
      return unauthorized(ex.getMessage());
    }
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

  private void ensurePasswordAuthEnabled() {
    if (!passwordAuthEnabled) {
      throw new ResponseStatusException(
          HttpStatus.FORBIDDEN,
          "Password auth is disabled. Use Google SSO.");
    }
  }
}
