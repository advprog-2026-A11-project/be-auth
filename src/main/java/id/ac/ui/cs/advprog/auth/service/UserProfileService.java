package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import java.util.List;
import java.util.Optional;
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
    return repository.save(user);
  }

  public List<UserProfile> findAll() {
    return repository.findAll();
  }

  public Optional<UserProfile> findById(Long id) {
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

  public boolean usernameExists(String username) {
    return repository.existsByUsername(username);
  }

  public boolean emailExists(String email) {
    return repository.existsByEmail(email);
  }

  public UserProfile upsertFromIdentity(String supabaseUserId, String email, String incomingRole) {
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
      if (!StringUtils.hasText(existing.getRole())) {
        existing.setRole(normalizeRole(incomingRole));
      }
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
      if (!StringUtils.hasText(existing.getRole())) {
        existing.setRole(normalizeRole(incomingRole));
      }
      return repository.save(existing);
    }

    UserProfile created = new UserProfile();
    created.setSupabaseUserId(supabaseUserId);
    created.setEmail(normalizedEmail);
    created.setUsername(generateUniqueUsername(normalizedEmail, supabaseUserId));
    created.setDisplayName(extractDisplayName(normalizedEmail));
    created.setRole(normalizeRole(incomingRole));
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

  public Optional<UserProfile> updateDisplayName(Long id, String newDisplayName) {
    return repository.findById(id).map(u -> {
      u.setDisplayName(newDisplayName);
      return repository.save(u);
    });
  }

  public Optional<UserProfile> update(Long id, UserProfile incoming) {
    return repository.findById(id).map(existing -> {
      existing.setUsername(incoming.getUsername());
      existing.setDisplayName(incoming.getDisplayName());
      existing.setRole(incoming.getRole());
      existing.setActive(incoming.isActive());

      if (incoming.getEmail() != null && !incoming.getEmail().isBlank()) {
        existing.setEmail(incoming.getEmail());
      }

      if (incoming.getPasswordHash() != null && !incoming.getPasswordHash().isBlank()) {
        existing.setPasswordHash(incoming.getPasswordHash());
      }

      return repository.save(existing);
    });
  }

  public void deleteById(Long id) {
    repository.deleteById(id);
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

    if (!repository.existsByUsername(base + "-" + supabaseUserId.substring(0, Math.min(6, supabaseUserId.length())))) {
      return base + "-" + supabaseUserId.substring(0, Math.min(6, supabaseUserId.length()));
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

  private String normalizeRole(String incomingRole) {
    if (!StringUtils.hasText(incomingRole)) {
      return "USER";
    }

    String normalized = incomingRole.trim().toUpperCase();
    if ("AUTHENTICATED".equals(normalized)) {
      return "USER";
    }
    if ("ADMIN".equals(normalized)) {
      return "ADMIN";
    }
    return "USER";
  }
}
