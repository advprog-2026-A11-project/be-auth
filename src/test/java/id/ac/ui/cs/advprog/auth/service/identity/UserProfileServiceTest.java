package id.ac.ui.cs.advprog.auth.service.identity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import id.ac.ui.cs.advprog.auth.service.supabase.SupabaseAuthClient;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class UserProfileServiceTest {

  @Mock
  private UserProfileRepository repository;

  @Mock
  private SupabaseAuthClient supabaseAuthClient;

  private UserProfileService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    service = new UserProfileService(
        repository,
        new UserProfileIdentitySyncService(repository, supabaseAuthClient));
  }

  @Test
  void createDelegatesToRepository() {
    UserProfile user = new UserProfile("u", "drift@example.com", "sub-123", "d", "USER", true);
    when(supabaseAuthClient.getUserById("sub-123")).thenReturn(new SupabaseAuthClient.IdentityUser(
        "sub-123",
        "provider@example.com",
        "authenticated",
        "password",
        null,
        "Provider Name"));
    when(repository.findBySupabaseUserId("sub-123")).thenReturn(Optional.empty());
    when(repository.findByEmail("provider@example.com")).thenReturn(Optional.empty());
    when(repository.existsByUsername("provider")).thenReturn(false);
    when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    UserProfile created = service.create(user);
    assertEquals("provider@example.com", created.getEmail());
    assertEquals("u", created.getUsername());
    verify(repository, atLeastOnce()).save(any());
  }

  @Test
  void findAllReturnsList() {
    List<UserProfile> list = Arrays.asList(new UserProfile(), new UserProfile());
    when(repository.findAll()).thenReturn(list);
    List<UserProfile> res = service.findAll();
    assertEquals(2, res.size());
  }

  @Test
  void findByIdDelegates() {
    UUID id = UUID.randomUUID();
    when(repository.findById(id)).thenReturn(Optional.of(new UserProfile()));
    assertTrue(service.findById(id).isPresent());
  }

  @Test
  void findPublicProfilesByIdsPreservesRequestOrderAndDeduplicatesIds() {
    UUID id1 = UUID.randomUUID();
    UUID id2 = UUID.randomUUID();
    UserProfile user1 = new UserProfile();
    user1.setId(id1);
    user1.setUsername("alpha");
    UserProfile user2 = new UserProfile();
    user2.setId(id2);
    user2.setUsername("beta");

    when(repository.findAllById(List.of(id2, id1))).thenReturn(List.of(user1, user2));

    List<UserProfile> profiles = service.findPublicProfilesByIds(List.of(id2, id1, id2));

    assertEquals(List.of(user2, user1), profiles);
    verify(repository).findAllById(List.of(id2, id1));
  }

  @Test
  void findByEmailDelegates() {
    when(repository.findByEmail("a@b")).thenReturn(Optional.of(new UserProfile()));
    assertTrue(service.findByEmail("a@b").isPresent());
  }

  @Test
  void deactivateByIdMarksExistingUserInactive() {
    UUID id = UUID.randomUUID();
    UserProfile existing = new UserProfile();
    existing.setActive(true);
    when(repository.findById(id)).thenReturn(Optional.of(existing));
    when(repository.save(any())).thenAnswer(i -> i.getArgument(0));

    UserProfile deactivated = service.deactivateById(id);

    assertFalse(deactivated.isActive());
    verify(repository).save(existing);
    verify(repository, never()).deleteById(any());
  }

  @Test
  void updateUsesSupabaseIdentityAsEmailSourceOfTruth() {
    UUID id = UUID.randomUUID();
    UserProfile existing = new UserProfile();
    existing.setId(id);
    existing.setSupabaseUserId("sub-123");
    existing.setEmail("old@example.com");
    existing.setUsername("old-user");
    existing.setDisplayName("Old Name");
    existing.setRole("STUDENT");
    existing.setActive(true);

    UserProfile incoming = new UserProfile();
    incoming.setUsername("new-user");
    incoming.setEmail("drift@example.com");
    incoming.setDisplayName("New Name");
    incoming.setRole("ADMIN");
    incoming.setActive(false);

    when(repository.findById(id)).thenReturn(Optional.of(existing));
    when(supabaseAuthClient.getUserById("sub-123")).thenReturn(new SupabaseAuthClient.IdentityUser(
        "sub-123",
        "provider@example.com",
        "authenticated",
        "password",
        null,
        "Provider Name"));
    when(repository.existsByUsername("new-user")).thenReturn(false);
    when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    Optional<UserProfile> updated = service.update(id, incoming);

    assertTrue(updated.isPresent());
    assertEquals("provider@example.com", updated.get().getEmail());
    assertEquals("new-user", updated.get().getUsername());
    assertEquals("ADMIN", updated.get().getRole());
    assertFalse(updated.get().isActive());
  }
}


