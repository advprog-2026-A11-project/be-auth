package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.model.RevokedAccessToken;
import id.ac.ui.cs.advprog.auth.repository.RevokedAccessTokenRepository;
import java.time.Instant;
import org.springframework.stereotype.Service;

@Service
public class JpaRevokedTokenStore implements RevokedTokenStore {

  private final RevokedAccessTokenRepository repository;

  public JpaRevokedTokenStore(RevokedAccessTokenRepository repository) {
    this.repository = repository;
  }

  @Override
  public void save(String tokenHash, Instant expiresAt, Instant now) {
    repository.deleteAllByExpiresAtLessThanEqual(now);
    repository.save(new RevokedAccessToken(tokenHash, expiresAt));
  }

  @Override
  public boolean exists(String tokenHash, Instant now) {
    repository.deleteAllByExpiresAtLessThanEqual(now);
    return repository.existsByTokenHashAndExpiresAtAfter(tokenHash, now);
  }
}
