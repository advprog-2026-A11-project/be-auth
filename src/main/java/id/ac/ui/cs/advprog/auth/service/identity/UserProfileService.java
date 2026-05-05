package id.ac.ui.cs.advprog.auth.service.identity;

import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.model.Role;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Predicate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class UserProfileService {

  private final UserProfileRepository repository;
  private final UserProfileIdentitySyncService identitySyncService;

  public UserProfileService(
      UserProfileRepository repository,
      UserProfileIdentitySyncService identitySyncService) {
    this.repository = repository;
    this.identitySyncService = identitySyncService;
  }

  public UserProfile create(UserProfile user) {
    UserProfile synced = identitySyncService.syncAdminUpdate(new UserProfile(), user);
    synced = identitySyncService.upsertFromIdentity(
        synced.getSupabaseUserId(),
        synced.getEmail(),
        user.getRole(),
        synced.getAuthProvider(),
        synced.getGoogleSub(),
        synced.getDisplayName());

    applyAdminManagedFields(synced, user);
    return repository.save(synced);
  }

  public List<UserProfile> findAll() {
    return repository.findAll();
  }

  public Optional<UserProfile> findById(UUID id) {
    return repository.findById(id);
  }

  public Optional<UserProfile> findByPublicUserId(String publicUserId) {
    if (!StringUtils.hasText(publicUserId)) {
      return Optional.empty();
    }

    try {
      return repository.findById(UUID.fromString(publicUserId.trim()));
    } catch (IllegalArgumentException ex) {
      return Optional.empty();
    }
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

  public Optional<UserProfile> findByPhone(String phone) {
    if (!StringUtils.hasText(phone)) {
      return Optional.empty();
    }
    return repository.findByPhone(phone.trim());
  }

  public UserProfile upsertFromIdentity(String supabaseUserId, String email, String incomingRole) {
    return identitySyncService.upsertFromIdentity(supabaseUserId, email, incomingRole);
  }

  public UserProfile updateCurrentUserProfile(
      String publicUserId,
      String username,
      String displayName) {
    return saveCurrentUser(publicUserId, existing -> applyProfileFields(existing, username, displayName));
  }

  public UserProfile updateIdentityProfile(
      String supabaseUserId,
      String email,
      String username,
      String displayName) {
    UserProfile existing = resolveProfileByIdentityOrThrow(supabaseUserId, email);
    applyProfileFields(existing, username, displayName);
    return repository.save(existing);
  }

  public UserProfile deactivateCurrentUser(String publicUserId) {
    return saveCurrentUser(publicUserId, existing -> existing.setActive(false));
  }

  public UserProfile updateCurrentUserEmail(
      String publicUserId,
      String newEmail) {
    return saveCurrentUser(publicUserId, existing -> existing.setEmail(
        requireUnique(
            existing.getEmail(),
            normalizeEmailOrThrow(newEmail),
            repository::existsByEmail,
            "Email already taken")));
  }

  public UserProfile updateCurrentUserPhone(
      String publicUserId,
      String newPhone) {
    return saveCurrentUser(publicUserId, existing -> existing.setPhone(
        requireUnique(
            existing.getPhone(),
            normalizePhoneOrThrow(newPhone),
            repository::existsByPhone,
            "Phone already taken")));
  }

  public Optional<UserProfile> update(UUID id, UserProfile incoming) {
    return repository.findById(id).map(existing -> {
      identitySyncService.syncAdminUpdate(existing, incoming);
      applyAdminManagedFields(existing, incoming);

      return repository.save(existing);
    });
  }

  public UserProfile deactivateById(UUID id) {
    return saveExistingById(id, existing -> existing.setActive(false));
  }

  public UserProfile activateById(UUID id) {
    return saveExistingById(id, existing -> existing.setActive(true));
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

  private void applyAdminManagedFields(UserProfile target, UserProfile incoming) {
    applyProfileFields(target, incoming.getUsername(), incoming.getDisplayName());

    if (StringUtils.hasText(incoming.getRole())) {
      target.setRole(Role.canonicalize(incoming.getRole()));
    } else if (!StringUtils.hasText(target.getRole())) {
      target.setRole("STUDENT");
    }

    target.setActive(incoming.isActive());
  }

  private UserProfile resolveProfileByIdentityOrThrow(String supabaseUserId, String email) {
    Optional<UserProfile> existing = Optional.empty();
    if (StringUtils.hasText(supabaseUserId)) {
      existing = repository.findBySupabaseUserId(supabaseUserId);
    }
    if (existing.isEmpty() && StringUtils.hasText(email)) {
      existing = repository.findByEmail(email.trim().toLowerCase());
    }
    return existing.orElseThrow(() -> new IllegalArgumentException("User profile not found"));
  }

  private UserProfile requireCurrentUserProfile(String publicUserId) {
    if (!StringUtils.hasText(publicUserId)) {
      throw new IllegalArgumentException("Authenticated public user id is required");
    }

    try {
      return repository.findById(UUID.fromString(publicUserId.trim()))
          .orElseThrow(() -> new IllegalArgumentException("User profile not found"));
    } catch (IllegalArgumentException ex) {
      if ("User profile not found".equals(ex.getMessage())) {
        throw ex;
      }
      throw new IllegalArgumentException("Authenticated public user id is invalid", ex);
    }
  }

  private void applyProfileFields(UserProfile existing, String username, String displayName) {
    if (StringUtils.hasText(username)) {
      existing.setUsername(requireUnique(
          existing.getUsername(),
          username.trim(),
          repository::existsByUsername,
          "Username already taken"));
    }

    if (displayName != null) {
      existing.setDisplayName(displayName.trim());
    }
  }

  private UserProfile saveCurrentUser(String publicUserId, Consumer<UserProfile> mutator) {
    UserProfile existing = requireCurrentUserProfile(publicUserId);
    mutator.accept(existing);
    return repository.save(existing);
  }

  private UserProfile saveExistingById(UUID id, Consumer<UserProfile> mutator) {
    return repository.findById(id).map(existing -> {
      mutator.accept(existing);
      return repository.save(existing);
    }).orElseThrow(() -> new IllegalArgumentException("User profile not found"));
  }

  private String requireUnique(
      String currentValue,
      String newValue,
      Predicate<String> existsCheck,
      String conflictMessage) {
    if (newValue.equals(currentValue)) {
      return newValue;
    }
    if (existsCheck.test(newValue)) {
      throw new ConflictException(conflictMessage);
    }
    return newValue;
  }

}


