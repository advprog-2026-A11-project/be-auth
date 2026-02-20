package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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
    return repository.findByEmail(email);
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
}
