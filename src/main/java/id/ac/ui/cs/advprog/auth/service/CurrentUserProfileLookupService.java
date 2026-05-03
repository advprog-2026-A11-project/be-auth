package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class CurrentUserProfileLookupService {

  private final UserProfileRepository repository;

  public CurrentUserProfileLookupService(UserProfileRepository repository) {
    this.repository = repository;
  }

  public UserProfile findCurrentUserOrThrow(String supabaseUserId, String email) {
    return findCurrentUser(supabaseUserId, email).orElseThrow(
        () -> new IllegalArgumentException("User profile not found"));
  }

  public Optional<UserProfile> findCurrentUser(String supabaseUserId, String email) {
    if (!StringUtils.hasText(supabaseUserId) && !StringUtils.hasText(email)) {
      throw new IllegalArgumentException("Authenticated user identity is required");
    }

    Optional<UserProfile> existing = StringUtils.hasText(supabaseUserId)
        ? repository.findBySupabaseUserId(supabaseUserId)
        : Optional.empty();

    if (existing.isEmpty() && StringUtils.hasText(email)) {
      existing = repository.findByEmail(email.trim().toLowerCase());
    }

    return existing;
  }
}
