package id.ac.ui.cs.advprog.auth.service.state;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import id.ac.ui.cs.advprog.auth.model.RevokedAccessToken;
import id.ac.ui.cs.advprog.auth.repository.RevokedAccessTokenRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

@DataJpaTest
@Import(JpaRevokedTokenStore.class)
class JpaRevokedTokenStoreTest {

  @Autowired
  private JpaRevokedTokenStore store;

  @Autowired
  private RevokedAccessTokenRepository repository;

  @Test
  void saveRemovesExpiredTokensBeforePersistingNewToken() {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    repository.save(new RevokedAccessToken("expired-hash", now.minusSeconds(1)));

    store.save("fresh-hash", now.plusSeconds(120), now);

    assertFalse(repository.existsById("expired-hash"));
    assertTrue(repository.existsById("fresh-hash"));
  }

  @Test
  void existsReturnsFalseForExpiredTokenAndCleansItUp() {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    repository.save(new RevokedAccessToken("expired-hash", now.minusSeconds(1)));

    boolean revoked = store.exists("expired-hash", now);

    assertFalse(revoked);
    assertFalse(repository.existsById("expired-hash"));
  }
}


