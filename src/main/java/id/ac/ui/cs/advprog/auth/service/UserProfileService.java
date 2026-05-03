package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.model.Role;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class UserProfileService {

  private final UserProfileRepository repository;
  private final UserProfileIdentitySyncService identitySyncService;
  private final CurrentUserProfileLookupService currentUserProfileLookupService;

  public UserProfileService(
      UserProfileRepository repository,
      UserProfileIdentitySyncService identitySyncService,
      CurrentUserProfileLookupService currentUserProfileLookupService) {
    this.repository = repository;
    this.identitySyncService = identitySyncService;
    this.currentUserProfileLookupService = currentUserProfileLookupService;
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
    return identitySyncService.upsertFromIdentity(supabaseUserId, email, incomingRole);
  }

  public UserProfile upsertFromIdentity(
      String supabaseUserId,
      String email,
      String incomingRole,
      String authProvider,
      String googleSub,
      String displayName) {
    return identitySyncService.upsertFromIdentity(
        supabaseUserId,
        email,
        incomingRole,
        authProvider,
        googleSub,
        displayName);
  }

  public UserProfile updateCurrentUserProfile(
      String supabaseUserId,
      String email,
      String username,
      String displayName) {
    UserProfile existing = findCurrentUserOrThrow(supabaseUserId, email);

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
    UserProfile existing = findCurrentUserOrThrow(supabaseUserId, email);

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
      identitySyncService.syncAdminUpdate(existing, incoming);
      applyAdminManagedFields(existing, incoming);

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

  private UserProfile findCurrentUserOrThrow(String supabaseUserId, String email) {
    return currentUserProfileLookupService.findCurrentUserOrThrow(supabaseUserId, email);
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
    if (StringUtils.hasText(incoming.getUsername())) {
      String normalizedUsername = incoming.getUsername().trim();
      if (!normalizedUsername.equals(target.getUsername())
          && repository.existsByUsername(normalizedUsername)) {
        throw new ConflictException("Username already taken");
      }
      target.setUsername(normalizedUsername);
    }

    if (incoming.getDisplayName() != null) {
      target.setDisplayName(incoming.getDisplayName().trim());
    }

    if (StringUtils.hasText(incoming.getRole())) {
      target.setRole(Role.canonicalize(incoming.getRole()));
    } else if (!StringUtils.hasText(target.getRole())) {
      target.setRole("STUDENT");
    }

    target.setActive(incoming.isActive());
  }

}
