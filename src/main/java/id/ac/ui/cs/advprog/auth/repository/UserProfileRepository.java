package id.ac.ui.cs.advprog.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import id.ac.ui.cs.advprog.auth.model.UserProfile;

@Repository
public interface UserProfileRepository extends JpaRepository<UserProfile, Long> {
  Optional<UserProfile> findByUsername(String username);

  Optional<UserProfile> findByEmail(String email);
}
