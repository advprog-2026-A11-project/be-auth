package id.ac.ui.cs.advprog.auth.service.state;

import java.time.Instant;

public interface RevokedTokenStore {

  void save(String tokenHash, Instant expiresAt, Instant now);

  boolean exists(String tokenHash, Instant now);
}


