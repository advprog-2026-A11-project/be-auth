package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

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

  public Optional<UserProfile> updateDisplayName(Long id, String newDisplayName) {
    return repository.findById(id).map(u -> {
      u.setDisplayName(newDisplayName);
      return repository.save(u);
    });
  }

  public void deleteById(Long id) {
    repository.deleteById(id);
  }
}
