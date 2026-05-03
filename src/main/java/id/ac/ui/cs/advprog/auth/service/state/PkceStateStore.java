package id.ac.ui.cs.advprog.auth.service.state;

import java.time.Instant;
import java.util.Optional;

public interface PkceStateStore {

  void save(String flowId, String codeVerifier, Instant expiresAt, String redirectUrl);

  Optional<PkceFlowState> take(String flowId, Instant now);

  record PkceFlowState(String codeVerifier, Instant expiresAt, String redirectUrl) {
  }
}


