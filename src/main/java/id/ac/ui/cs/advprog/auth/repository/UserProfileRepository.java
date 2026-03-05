package id.ac.ui.cs.advprog.auth.repository;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserProfileRepository extends JpaRepository<UserProfile, Long> {
  Optional<UserProfile> findByUsername(String username);

  Optional<UserProfile> findByEmail(String email);

  Optional<UserProfile> findBySupabaseUserId(String supabaseUserId);

  boolean existsByUsername(String username);

  boolean existsByEmail(String email);
}
