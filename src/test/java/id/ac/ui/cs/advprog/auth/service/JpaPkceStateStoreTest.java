package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import id.ac.ui.cs.advprog.auth.model.GoogleSsoPkceState;
import id.ac.ui.cs.advprog.auth.repository.GoogleSsoPkceStateRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

@DataJpaTest
@Import(JpaPkceStateStore.class)
class JpaPkceStateStoreTest {

  @Autowired
  private JpaPkceStateStore store;

  @Autowired
  private GoogleSsoPkceStateRepository repository;

  @Test
  void savePersistsStateForLaterConsumption() {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");

    store.save(
        "flow-id",
        "verifier",
        now.plusSeconds(300),
        "https://app.test/callback?app_state=flow-id");

    assertTrue(repository.existsById("flow-id"));
  }

  @Test
  void takeReturnsStoredStateAndDeletesIt() {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    repository.save(new GoogleSsoPkceState(
        "flow-id",
        "verifier",
        now.plusSeconds(300),
        "https://app.test/callback?app_state=flow-id"));

    var state = store.take("flow-id", now);

    assertTrue(state.isPresent());
    assertEquals("verifier", state.get().codeVerifier());
    assertEquals("https://app.test/callback?app_state=flow-id", state.get().redirectUrl());
    assertFalse(repository.existsById("flow-id"));
  }

  @Test
  void takeRejectsExpiredStateAndCleansItUp() {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    repository.save(new GoogleSsoPkceState(
        "expired-flow",
        "verifier",
        now.minusSeconds(1),
        "https://app.test/callback?app_state=expired-flow"));

    var state = store.take("expired-flow", now);

    assertTrue(state.isEmpty());
    assertFalse(repository.existsById("expired-flow"));
  }
}
