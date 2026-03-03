package id.ac.ui.cs.advprog.auth.controller;

import id.ac.ui.cs.advprog.auth.dto.auth.LoginRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.LoginResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.SupabaseJwtService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private static final String EMAIL_CLAIM = "email";

  private final SupabaseJwtService supabaseJwtService;
  private final UserProfileService userProfileService;

  public AuthController(
      SupabaseJwtService supabaseJwtService,
      UserProfileService userProfileService) {
    this.supabaseJwtService = supabaseJwtService;
    this.userProfileService = userProfileService;
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
      Optional<UserProfile> profile = Optional.empty();
      if (StringUtils.hasText(sub)) {
        profile = safeOptional(userProfileService.findBySupabaseUserId(sub));
      }
      if (profile.isEmpty() && StringUtils.hasText(email)) {
        profile = safeOptional(userProfileService.findByEmail(email));
      }

      Map<String, Object> payload = new HashMap<>();
      payload.put("sub", sub);
      payload.put(EMAIL_CLAIM, email);
      payload.put("role", claims.getClaimAsString("role"));
      payload.put("aud", claims.getAudience());
      payload.put("iss", claims.getIssuer());
      payload.put("exp", claims.getExpiresAt());

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
    return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(LoginResponse.contractOnly());
  }

  @GetMapping("/sso/google/url")
  public ResponseEntity<SsoUrlResponse> googleSsoUrl() {
    return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
        .body(SsoUrlResponse.contractOnly("google"));
  }

  @PostMapping("/sso/google/callback")
  public ResponseEntity<SsoCallbackResponse> googleSsoCallback(
      @Valid @RequestBody SsoCallbackRequest request) {
    return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(SsoCallbackResponse.contractOnly());
  }

  private ResponseEntity<Map<String, Object>> unauthorized(String message) {
    Map<String, Object> response = new HashMap<>();
    response.put("error", message);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
  }

  private Optional<UserProfile> safeOptional(Optional<UserProfile> value) {
    return value == null ? Optional.empty() : value;
  }
}
