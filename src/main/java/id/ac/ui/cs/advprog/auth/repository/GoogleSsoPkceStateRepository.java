package id.ac.ui.cs.advprog.auth.repository;

import id.ac.ui.cs.advprog.auth.model.GoogleSsoPkceState;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

public interface GoogleSsoPkceStateRepository extends JpaRepository<GoogleSsoPkceState, String> {

  void deleteAllByExpiresAtLessThanEqual(Instant expiresAt);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select state from GoogleSsoPkceState state where state.flowId = :flowId")
  Optional<GoogleSsoPkceState> findByFlowIdForUpdate(@Param("flowId") String flowId);
}
