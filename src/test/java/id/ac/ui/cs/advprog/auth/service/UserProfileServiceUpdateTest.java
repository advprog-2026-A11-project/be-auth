package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.exception.ConflictException;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.Optional;
import java.util.UUID;
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
  void updateAppliesEmailWhenProvided() {
    UUID id = UUID.randomUUID();
    UserProfile existing = new UserProfile("u", "old@e", "name", "USER", true);
    when(repository.findById(id)).thenReturn(Optional.of(existing));
    when(repository.save(any())).thenAnswer(i -> i.getArgument(0));

    UserProfile incoming = new UserProfile();
    incoming.setEmail("new@e");
    incoming.setUsername("u2");
    incoming.setDisplayName("dn");
    incoming.setRole("ADMIN");
    incoming.setActive(false);

    Optional<UserProfile> out = service.update(id, incoming);
    assertTrue(out.isPresent());
    UserProfile updated = out.get();
    assertEquals("new@e", updated.getEmail());
    assertEquals("u2", updated.getUsername());
  }

  @Test
  void updateSkipsEmailWhenBlank() {
    UUID id = UUID.randomUUID();
    UserProfile existing = new UserProfile("u", "old@e", "name", "USER", true);
    when(repository.findById(id)).thenReturn(Optional.of(existing));
    when(repository.save(any())).thenAnswer(i -> i.getArgument(0));

    UserProfile incoming = new UserProfile();
    incoming.setEmail("");
    incoming.setUsername("u3");

    Optional<UserProfile> out = service.update(id, incoming);
    assertTrue(out.isPresent());
    UserProfile updated = out.get();
    assertEquals("old@e", updated.getEmail());
    assertEquals("u3", updated.getUsername());
  }

  @Test
  void updateReturnsEmptyWhenNotFound() {
    UUID id = UUID.randomUUID();
    when(repository.findById(id)).thenReturn(Optional.empty());
    UserProfile incoming = new UserProfile();
    Optional<UserProfile> out = service.update(id, incoming);
    assertTrue(out.isEmpty());
  }

  @Test
  void updateCurrentUserEmailNormalizesAndSaves() {
    UserProfile existing = new UserProfile("user", "old@example.com", "name", "USER", true);
    existing.setSupabaseUserId("sub-123");
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.of(existing));
    when(repository.existsByEmail("new@example.com")).thenReturn(false);
    when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    UserProfile updated = service.updateCurrentUserEmail(
        "sub-123",
        "old@example.com",
        "  New@Example.com  ");

    assertEquals("new@example.com", updated.getEmail());
    verify(repository).existsByEmail("new@example.com");
  }

  @Test
  void updateCurrentUserEmailRejectsDuplicate() {
    UserProfile existing = new UserProfile("user", "old@example.com", "name", "USER", true);
    existing.setSupabaseUserId("sub-123");
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.of(existing));
    when(repository.existsByEmail("taken@example.com")).thenReturn(true);

    ConflictException ex = assertThrows(
        ConflictException.class,
        () -> service.updateCurrentUserEmail(
            "sub-123",
            "old@example.com",
            "taken@example.com"));

    assertEquals("Email already taken", ex.getMessage());
  }

  @Test
  void updateCurrentUserPhoneNormalizesAndSaves() {
    UserProfile existing = new UserProfile("user", "old@example.com", "name", "USER", true);
    existing.setSupabaseUserId("sub-123");
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.of(existing));
    when(repository.existsByPhone("+628123456789")).thenReturn(false);
    when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    UserProfile updated = service.updateCurrentUserPhone(
        "sub-123",
        "old@example.com",
        "  +628123456789  ");

    assertEquals("+628123456789", updated.getPhone());
    verify(repository).existsByPhone("+628123456789");
  }

  @Test
  void updateCurrentUserPhoneRejectsDuplicate() {
    UserProfile existing = new UserProfile("user", "old@example.com", "name", "USER", true);
    existing.setSupabaseUserId("sub-123");
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.of(existing));
    when(repository.existsByPhone("+628999999999")).thenReturn(true);

    ConflictException ex = assertThrows(
        ConflictException.class,
        () -> service.updateCurrentUserPhone(
            "sub-123",
            "old@example.com",
            "+628999999999"));

    assertEquals("Phone already taken", ex.getMessage());
  }
}
