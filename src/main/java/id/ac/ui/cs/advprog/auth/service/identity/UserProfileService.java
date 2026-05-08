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
  private static final String AUTH_PROVIDER_GOOGLE = "GOOGLE";
  private static final String AUTH_PROVIDER_GOOGLE_PASSWORD = "GOOGLE_PASSWORD";
  private static final String AUTH_PROVIDER_PASSWORD = "PASSWORD";

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

  public List<UserProfile> findPublicProfilesByIds(List<UUID> userIds) {
    if (userIds == null || userIds.isEmpty()) {
      return List.of();
    }

    List<UUID> distinctIds = userIds.stream().distinct().toList();
    List<UserProfile> profiles = repository.findAllById(distinctIds);

    return distinctIds.stream()
        .flatMap(
            id -> profiles.stream()
                .filter(profile -> id.equals(profile.getId()))
                .findFirst()
                .stream())
        .toList();
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
    return normalizePhone(phone).flatMap(repository::findByPhone);
  }

  public UserProfile upsertFromIdentity(String supabaseUserId, String email, String incomingRole) {
    return identitySyncService.upsertFromIdentity(supabaseUserId, email, incomingRole);
  }

  public UserProfile updateCurrentUserProfile(
      String publicUserId,
      String username,
      String displayName) {
    return saveCurrentUser(
        publicUserId,
        existing -> applyProfileFields(existing, username, displayName));
  }

  public UserProfile updateIdentityProfile(
      String supabaseUserId,
      String email,
      String username,
      String displayName) {
    return updateIdentityProfile(supabaseUserId, email, username, displayName, null);
  }

  public UserProfile updateIdentityProfile(
      String supabaseUserId,
      String email,
      String username,
      String displayName,
      String phone) {
    UserProfile existing = resolveProfileByIdentityOrThrow(supabaseUserId, email);
    applyProfileFields(existing, username, displayName, phone);
    return repository.save(existing);
  }

  public UserProfile deactivateCurrentUser(String publicUserId) {
    return saveCurrentUser(publicUserId, existing -> existing.setActive(false));
  }

  public UserProfile updateCurrentUserEmail(
      String publicUserId,
      String newEmail) {
    return saveCurrentUser(publicUserId, existing -> {
      String normalizedEmail = normalizeEmailOrThrow(newEmail);
      validateUnique(
          existing.getEmail(),
          normalizedEmail,
          repository::existsByEmail,
          "Email already taken");
      existing.setEmail(normalizedEmail);
    });
  }

  public UserProfile updateCurrentUserPhone(
      String publicUserId,
      String newPhone) {
    return saveCurrentUser(publicUserId, existing -> {
      String normalizedPhone = normalizePhoneOrThrow(newPhone);
      validateUnique(
          existing.getPhone(),
          normalizedPhone,
          repository::existsByPhone,
          "Phone already taken");
      existing.setPhone(normalizedPhone);
    });
  }

  public UserProfile markCurrentUserPasswordEnabled(String publicUserId) {
    return saveCurrentUser(publicUserId, existing -> existing.setAuthProvider(
        mergeAuthProvider(existing.getAuthProvider(), AUTH_PROVIDER_PASSWORD)));
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
    return normalizePhone(phone)
        .orElseThrow(() -> new IllegalArgumentException("phone is required"));
  }

  private Optional<String> normalizePhone(String phone) {
    if (!StringUtils.hasText(phone)) {
      return Optional.empty();
    }

    String compact = phone.trim().replaceAll("[\\s\\-()]", "");
    if (!StringUtils.hasText(compact)) {
      return Optional.empty();
    }

    if (compact.startsWith("08")) {
      compact = "+628" + compact.substring(2);
    } else if (compact.startsWith("628")) {
      compact = "+" + compact;
    }

    return Optional.of(compact);
  }

  private void applyAdminManagedFields(UserProfile target, UserProfile incoming) {
    applyProfileFields(target, incoming.getUsername(), incoming.getDisplayName(), null);

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
    applyProfileFields(existing, username, displayName, null);
  }

  private void applyProfileFields(
      UserProfile existing,
      String username,
      String displayName,
      String phone) {
    if (StringUtils.hasText(username)) {
      String normalizedUsername = username.trim();
      validateUnique(
          existing.getUsername(),
          normalizedUsername,
          repository::existsByUsername,
          "Username already taken");
      existing.setUsername(normalizedUsername);
    }

    if (displayName != null) {
      existing.setDisplayName(displayName.trim());
    }

    if (phone != null) {
      String normalizedPhone = normalizePhoneOrThrow(phone);
      validateUnique(
          existing.getPhone(),
          normalizedPhone,
          repository::existsByPhone,
          "Phone already taken");
      existing.setPhone(normalizedPhone);
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

  private void validateUnique(
      String currentValue,
      String newValue,
      Predicate<String> existsCheck,
      String conflictMessage) {
    if (newValue.equals(currentValue)) {
      return;
    }
    if (existsCheck.test(newValue)) {
      throw new ConflictException(conflictMessage);
    }
  }

  private String mergeAuthProvider(String currentValue, String nextProvider) {
    boolean hasGoogle = containsProvider(currentValue, AUTH_PROVIDER_GOOGLE)
        || containsProvider(nextProvider, AUTH_PROVIDER_GOOGLE);
    boolean hasPassword = containsProvider(currentValue, AUTH_PROVIDER_PASSWORD)
        || containsProvider(nextProvider, AUTH_PROVIDER_PASSWORD);

    if (hasGoogle && hasPassword) {
      return AUTH_PROVIDER_GOOGLE_PASSWORD;
    }
    if (hasGoogle) {
      return AUTH_PROVIDER_GOOGLE;
    }
    if (hasPassword) {
      return AUTH_PROVIDER_PASSWORD;
    }
    return StringUtils.hasText(nextProvider)
        ? nextProvider.trim().toUpperCase()
        : AUTH_PROVIDER_PASSWORD;
  }

  private boolean containsProvider(String authProvider, String provider) {
    if (!StringUtils.hasText(authProvider)) {
      return false;
    }
    return authProvider.trim().toUpperCase().contains(provider);
  }

}

