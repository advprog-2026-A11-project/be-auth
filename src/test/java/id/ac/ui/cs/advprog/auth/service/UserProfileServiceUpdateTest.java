package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.util.Optional;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class UserProfileServiceUpdateTest {

  @Mock
  private UserProfileRepository repository;

  @InjectMocks
  private UserProfileService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void updateAppliesEmailAndPasswordWhenProvided() {
    UserProfile existing = new UserProfile("u", "old@e", "name", "oldhash", "USER", true);
    when(repository.findById(7L)).thenReturn(Optional.of(existing));
    when(repository.save(any())).thenAnswer(i -> i.getArgument(0));

    UserProfile incoming = new UserProfile();
    incoming.setEmail("new@e");
    incoming.setPasswordHash("newhash");
    incoming.setUsername("u2");
    incoming.setDisplayName("dn");
    incoming.setRole("ADMIN");
    incoming.setActive(false);

    Optional<UserProfile> out = service.update(7L, incoming);
    assertTrue(out.isPresent());
    UserProfile updated = out.get();
    assertEquals("new@e", updated.getEmail());
    assertEquals("newhash", updated.getPasswordHash());
    assertEquals("u2", updated.getUsername());
  }

  @Test
  void updateSkipsEmailAndPasswordWhenBlank() {
    UserProfile existing = new UserProfile("u", "old@e", "name", "oldhash", "USER", true);
    when(repository.findById(8L)).thenReturn(Optional.of(existing));
    when(repository.save(any())).thenAnswer(i -> i.getArgument(0));

    UserProfile incoming = new UserProfile();
    incoming.setEmail("");
    incoming.setPasswordHash("");
    incoming.setUsername("u3");

    Optional<UserProfile> out = service.update(8L, incoming);
    assertTrue(out.isPresent());
    UserProfile updated = out.get();
    assertEquals("old@e", updated.getEmail());
    assertEquals("oldhash", updated.getPasswordHash());
    assertEquals("u3", updated.getUsername());
  }

  @Test
  void updateReturnsEmptyWhenNotFound() {
    when(repository.findById(9L)).thenReturn(Optional.empty());
    UserProfile incoming = new UserProfile();
    Optional<UserProfile> out = service.update(9L, incoming);
    assertTrue(out.isEmpty());
  }
}
