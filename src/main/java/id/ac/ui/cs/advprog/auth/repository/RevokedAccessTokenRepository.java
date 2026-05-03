package id.ac.ui.cs.advprog.auth.repository;

import id.ac.ui.cs.advprog.auth.model.RevokedAccessToken;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RevokedAccessTokenRepository extends JpaRepository<RevokedAccessToken, String> {

  void deleteAllByExpiresAtLessThanEqual(Instant expiresAt);

  boolean existsByTokenHashAndExpiresAtAfter(String tokenHash, Instant expiresAt);
}
