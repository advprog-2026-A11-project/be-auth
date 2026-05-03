package id.ac.ui.cs.advprog.auth.service.identity;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class CurrentUserProfileLookupService {

  private final UserProfileRepository repository;

  public CurrentUserProfileLookupService(UserProfileRepository repository) {
    this.repository = repository;
  }

  public UserProfile findCurrentUserOrThrow(String publicUserId) {
    return findCurrentUser(publicUserId).orElseThrow(
        () -> new IllegalArgumentException("User profile not found"));
  }

  public Optional<UserProfile> findCurrentUser(String publicUserId) {
    if (!StringUtils.hasText(publicUserId)) {
      throw new IllegalArgumentException("Authenticated public user id is required");
    }

    try {
      return repository.findById(UUID.fromString(publicUserId.trim()));
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException("Authenticated public user id is invalid", ex);
    }
  }
}


