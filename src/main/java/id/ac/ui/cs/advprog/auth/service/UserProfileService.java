package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class UserProfileService {

  private final UserProfileRepository repository;

  @Autowired
  public UserProfileService(UserProfileRepository repository) {
    this.repository = repository;
  }

  public UserProfile create(UserProfile user) {
    user.setRole(RoleMapper.canonicalize(user.getRole()));
    return repository.save(user);
  }

  public List<UserProfile> findAll() {
    return repository.findAll();
  }

  public Optional<UserProfile> findById(UUID id) {
    return repository.findById(id);
  }

  public Optional<UserProfile> findByEmail(String email) {
    if (!StringUtils.hasText(email)) {
      return Optional.empty();
    }
    return repository.findByEmail(email.trim().toLowerCase());
  }

  public Optional<UserProfile> findByUsername(String username) {
    return repository.findByUsername(username);
  }

  public Optional<UserProfile> findBySupabaseUserId(String supabaseUserId) {
    return repository.findBySupabaseUserId(supabaseUserId);
  }

  public Optional<UserProfile> findByPhone(String phone) {
    if (!StringUtils.hasText(phone)) {
      return Optional.empty();
    }
    return repository.findByPhone(phone.trim());
  }

  public boolean usernameExists(String username) {
    return repository.existsByUsername(username);
  }

  public boolean emailExists(String email) {
    return repository.existsByEmail(email);
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

    String normalizedEmail = StringUtils.hasText(email)
        ? email.trim().toLowerCase()
        : (supabaseUserId + "@local.test");

    Optional<UserProfile> bySub = repository.findBySupabaseUserId(supabaseUserId);
    if (bySub.isPresent()) {
      UserProfile existing = bySub.get();
      existing.setEmail(normalizedEmail);
      existing.setRole(RoleMapper.canonicalize(existing.getRole()));
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
      existing.setRole(RoleMapper.canonicalize(existing.getRole()));
      applyIdentityEnrichment(existing, authProvider, googleSub, displayName);
      return repository.save(existing);
    }

    UserProfile created = new UserProfile();
    created.setSupabaseUserId(supabaseUserId);
    created.setEmail(normalizedEmail);
    created.setUsername(generateUniqueUsername(normalizedEmail, supabaseUserId));
    created.setDisplayName(resolveDisplayName(normalizedEmail, displayName));
    created.setRole(RoleMapper.canonicalize(incomingRole));
    created.setAuthProvider(resolveAuthProvider(authProvider));
    created.setGoogleSub(normalizeOptionalValue(googleSub));
    created.setActive(true);
    return repository.save(created);
  }

  public UserProfile updateCurrentUserProfile(
      String supabaseUserId,
      String email,
      String username,
      String displayName) {
    if (!StringUtils.hasText(supabaseUserId) && !StringUtils.hasText(email)) {
      throw new IllegalArgumentException("Authenticated user identity is required");
    }

    Optional<UserProfile> existingOptional = StringUtils.hasText(supabaseUserId)
        ? repository.findBySupabaseUserId(supabaseUserId)
        : Optional.empty();

    if (existingOptional.isEmpty() && StringUtils.hasText(email)) {
      existingOptional = repository.findByEmail(email.trim().toLowerCase());
    }

    UserProfile existing = existingOptional
        .orElseThrow(() -> new IllegalArgumentException("User profile not found"));

    if (StringUtils.hasText(username)) {
      String normalizedUsername = username.trim();
      if (!normalizedUsername.equals(existing.getUsername())
          && repository.existsByUsername(normalizedUsername)) {
        throw new ConflictException("Username already taken");
      }
      existing.setUsername(normalizedUsername);
    }

    if (displayName != null) {
      existing.setDisplayName(displayName.trim());
    }

    return repository.save(existing);
  }

  public UserProfile deactivateCurrentUser(String supabaseUserId, String email) {
    if (!StringUtils.hasText(supabaseUserId) && !StringUtils.hasText(email)) {
      throw new IllegalArgumentException("Authenticated user identity is required");
    }

    Optional<UserProfile> existingOptional = StringUtils.hasText(supabaseUserId)
        ? repository.findBySupabaseUserId(supabaseUserId)
        : Optional.empty();

    if (existingOptional.isEmpty() && StringUtils.hasText(email)) {
      existingOptional = repository.findByEmail(email.trim().toLowerCase());
    }

    UserProfile existing = existingOptional
        .orElseThrow(() -> new IllegalArgumentException("User profile not found"));

    existing.setActive(false);
    return repository.save(existing);
  }

  public UserProfile updateCurrentUserEmail(
      String supabaseUserId,
      String email,
      String newEmail) {
    UserProfile existing = findCurrentUserOrThrow(supabaseUserId, email);
    String normalizedEmail = normalizeEmailOrThrow(newEmail);

    if (!normalizedEmail.equals(existing.getEmail())
        && repository.existsByEmail(normalizedEmail)) {
      throw new ConflictException("Email already taken");
    }

    existing.setEmail(normalizedEmail);
    return repository.save(existing);
  }

  public UserProfile updateCurrentUserPhone(
      String supabaseUserId,
      String email,
      String newPhone) {
    UserProfile existing = findCurrentUserOrThrow(supabaseUserId, email);
    String normalizedPhone = normalizePhoneOrThrow(newPhone);

    if (!normalizedPhone.equals(existing.getPhone())
        && repository.existsByPhone(normalizedPhone)) {
      throw new ConflictException("Phone already taken");
    }

    existing.setPhone(normalizedPhone);
    return repository.save(existing);
  }

  public Optional<UserProfile> updateDisplayName(UUID id, String newDisplayName) {
    return repository.findById(id).map(u -> {
      u.setDisplayName(newDisplayName);
      return repository.save(u);
    });
  }

  public Optional<UserProfile> update(UUID id, UserProfile incoming) {
    return repository.findById(id).map(existing -> {
      existing.setUsername(incoming.getUsername());
      existing.setDisplayName(incoming.getDisplayName());
      existing.setRole(RoleMapper.canonicalize(incoming.getRole()));
      existing.setActive(incoming.isActive());

      if (incoming.getEmail() != null && !incoming.getEmail().isBlank()) {
        existing.setEmail(incoming.getEmail());
      }

      return repository.save(existing);
    });
  }

  public UserProfile deactivateById(UUID id) {
    return repository.findById(id).map(existing -> {
      existing.setActive(false);
      return repository.save(existing);
    }).orElseThrow(() -> new IllegalArgumentException("User profile not found"));
  }

  public UserProfile activateById(UUID id) {
    return repository.findById(id).map(existing -> {
      existing.setActive(true);
      return repository.save(existing);
    }).orElseThrow(() -> new IllegalArgumentException("User profile not found"));
  }

  public void deleteById(UUID id) {
    deactivateById(id);
  }

  private UserProfile findCurrentUserOrThrow(String supabaseUserId, String email) {
    if (!StringUtils.hasText(supabaseUserId) && !StringUtils.hasText(email)) {
      throw new IllegalArgumentException("Authenticated user identity is required");
    }

    Optional<UserProfile> existingOptional = StringUtils.hasText(supabaseUserId)
        ? repository.findBySupabaseUserId(supabaseUserId)
        : Optional.empty();

    if (existingOptional.isEmpty() && StringUtils.hasText(email)) {
      existingOptional = repository.findByEmail(email.trim().toLowerCase());
    }

    return existingOptional.orElseThrow(
        () -> new IllegalArgumentException("User profile not found"));
  }

  private String normalizeEmailOrThrow(String email) {
    if (!StringUtils.hasText(email)) {
      throw new IllegalArgumentException("email is required");
    }
    return email.trim().toLowerCase();
  }

  private String normalizePhoneOrThrow(String phone) {
    if (!StringUtils.hasText(phone)) {
      throw new IllegalArgumentException("phone is required");
    }
    return phone.trim();
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

}
