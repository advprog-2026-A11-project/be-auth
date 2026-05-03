package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.model.Role;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class UserProfileIdentitySyncService {

  private final UserProfileRepository repository;
  private final SupabaseAuthClient supabaseAuthClient;

  public UserProfileIdentitySyncService(
      UserProfileRepository repository,
      SupabaseAuthClient supabaseAuthClient) {
    this.repository = repository;
    this.supabaseAuthClient = supabaseAuthClient;
  }

  public UserProfile upsertFromIdentity(String supabaseUserId, String email, String incomingRole) {
    return upsertFromIdentity(supabaseUserId, email, incomingRole, "PASSWORD", null, null);
  }

  public UserProfile upsertFromIdentity(
      String supabaseUserId,
      String email,
      String incomingRole,
      String authProvider,
      String googleSub,
      String displayName) {
    if (!StringUtils.hasText(supabaseUserId)) {
      throw new IllegalArgumentException("supabaseUserId is required");
    }

    String normalizedEmail = normalizeEmail(email, supabaseUserId);
    Optional<UserProfile> bySub = repository.findBySupabaseUserId(supabaseUserId);
    if (bySub.isPresent()) {
      UserProfile existing = bySub.get();
      existing.setEmail(normalizedEmail);
      existing.setRole(Role.canonicalize(existing.getRole()));
      applyIdentityEnrichment(existing, authProvider, googleSub, displayName);
      return repository.save(existing);
    }

    Optional<UserProfile> byEmail = repository.findByEmail(normalizedEmail);
    if (byEmail.isPresent()) {
      UserProfile existing = byEmail.get();
      if (StringUtils.hasText(existing.getSupabaseUserId())
          && !supabaseUserId.equals(existing.getSupabaseUserId())) {
        throw new ConflictException("Identity conflict for email");
      }
      existing.setSupabaseUserId(supabaseUserId);
      existing.setRole(Role.canonicalize(existing.getRole()));
      applyIdentityEnrichment(existing, authProvider, googleSub, displayName);
      return repository.save(existing);
    }

    UserProfile created = new UserProfile();
    created.setSupabaseUserId(supabaseUserId);
    created.setEmail(normalizedEmail);
    created.setUsername(generateUniqueUsername(normalizedEmail, supabaseUserId));
    created.setDisplayName(resolveDisplayName(normalizedEmail, displayName));
    created.setRole(Role.canonicalize(incomingRole));
    created.setAuthProvider(resolveAuthProvider(authProvider));
    created.setGoogleSub(normalizeOptionalValue(googleSub));
    created.setActive(true);
    return repository.save(created);
  }

  public UserProfile syncAdminUpdate(UserProfile existing, UserProfile incoming) {
    String supabaseUserId = StringUtils.hasText(incoming.getSupabaseUserId())
        ? incoming.getSupabaseUserId().trim()
        : existing.getSupabaseUserId();

    if (StringUtils.hasText(supabaseUserId)) {
      SupabaseAuthClient.IdentityUser identity =
          supabaseAuthClient.getUserById(requireSupabaseUserId(supabaseUserId));

      existing.setSupabaseUserId(identity.supabaseUserId());
      existing.setEmail(normalizeEmailOrThrow(identity.email()));
      applyIdentityEnrichment(
          existing,
          identity.authProvider(),
          identity.googleSub(),
          identity.displayName());
      return existing;
    }

    applyLocalAdminEmail(existing, incoming);
    return existing;
  }

  private String normalizeEmail(String email, String supabaseUserId) {
    return StringUtils.hasText(email)
        ? email.trim().toLowerCase()
        : (supabaseUserId + "@local.test");
  }

  private String normalizeEmailOrThrow(String email) {
    if (!StringUtils.hasText(email)) {
      throw new IllegalArgumentException("email is required");
    }
    return email.trim().toLowerCase();
  }

  private String generateUniqueUsername(String email, String supabaseUserId) {
    String base = sanitizeUsernameCandidate(email);
    String candidate = base;
    int counter = 1;

    while (repository.existsByUsername(candidate)) {
      candidate = base + "-" + counter;
      counter++;
    }

    if (counter == 1) {
      return candidate;
    }

    String suffix = supabaseUserId.substring(0, Math.min(6, supabaseUserId.length()));
    String suffixedCandidate = base + "-" + suffix;
    if (!repository.existsByUsername(suffixedCandidate)) {
      return suffixedCandidate;
    }

    return candidate;
  }

  private String sanitizeUsernameCandidate(String email) {
    String localPart = email;
    int atIndex = email.indexOf("@");
    if (atIndex > 0) {
      localPart = email.substring(0, atIndex);
    }

    String sanitized = localPart.replaceAll("[^A-Za-z0-9._-]", "-").trim();
    if (!StringUtils.hasText(sanitized)) {
      return "user";
    }
    if (sanitized.length() < 3) {
      return (sanitized + "user").substring(0, 4);
    }
    return sanitized;
  }

  private String extractDisplayName(String email) {
    int atIndex = email.indexOf("@");
    return atIndex > 0 ? email.substring(0, atIndex) : email;
  }

  private void applyLocalAdminEmail(UserProfile target, UserProfile incoming) {
    if (!StringUtils.hasText(incoming.getEmail())) {
      return;
    }

    String normalizedEmail = normalizeEmailOrThrow(incoming.getEmail());
    if (!normalizedEmail.equals(target.getEmail()) && repository.existsByEmail(normalizedEmail)) {
      throw new ConflictException("Email already taken");
    }

    target.setEmail(normalizedEmail);
  }

  private void applyIdentityEnrichment(
      UserProfile user,
      String authProvider,
      String googleSub,
      String displayName) {
    user.setAuthProvider(resolveAuthProvider(authProvider));
    if (StringUtils.hasText(googleSub)) {
      user.setGoogleSub(googleSub.trim());
    }
    if (!StringUtils.hasText(user.getDisplayName()) && StringUtils.hasText(displayName)) {
      user.setDisplayName(displayName.trim());
    }
  }

  private String resolveDisplayName(String email, String displayName) {
    if (StringUtils.hasText(displayName)) {
      return displayName.trim();
    }
    return extractDisplayName(email);
  }

  private String resolveAuthProvider(String authProvider) {
    if (!StringUtils.hasText(authProvider)) {
      return "PASSWORD";
    }
    return authProvider.trim().toUpperCase();
  }

  private String normalizeOptionalValue(String value) {
    return StringUtils.hasText(value) ? value.trim() : null;
  }

  private String requireSupabaseUserId(String supabaseUserId) {
    if (!StringUtils.hasText(supabaseUserId)) {
      throw new IllegalArgumentException("supabaseUserId is required");
    }
    return supabaseUserId.trim();
  }
}
