package id.ac.ui.cs.advprog.auth.service.state;

import id.ac.ui.cs.advprog.auth.model.GoogleSsoPkceState;
import id.ac.ui.cs.advprog.auth.repository.GoogleSsoPkceStateRepository;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class JpaPkceStateStore implements PkceStateStore {

  private final GoogleSsoPkceStateRepository repository;

  public JpaPkceStateStore(GoogleSsoPkceStateRepository repository) {
    this.repository = repository;
  }

  @Override
  public void save(String flowId, String codeVerifier, Instant expiresAt, String redirectUrl) {
    repository.save(new GoogleSsoPkceState(flowId, codeVerifier, expiresAt, redirectUrl));
  }

  @Override
  @Transactional
  public Optional<PkceFlowState> take(String flowId, Instant now) {
    repository.deleteAllByExpiresAtLessThanEqual(now);

    return repository.findByFlowIdForUpdate(flowId)
        .map(state -> {
          repository.delete(state);
          return new PkceFlowState(
              state.getCodeVerifier(),
              state.getExpiresAt(),
              state.getRedirectUrl());
        });
  }
}


