package id.ac.ui.cs.advprog.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.repository.UserProfileRepository;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class UserProfileServiceTest {

  @Mock
  private UserProfileRepository repository;

  @InjectMocks
  private UserProfileService service;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void createDelegatesToRepository() {
    UserProfile user = new UserProfile("u", "e", "d", "USER", true);
    when(repository.save(any())).thenReturn(user);
    UserProfile created = service.create(user);
    assertSame(user, created);
    verify(repository).save(user);
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
    when(repository.findById(1L)).thenReturn(Optional.of(new UserProfile()));
    assertTrue(service.findById(1L).isPresent());
  }

  @Test
  void findByEmailDelegates() {
    when(repository.findByEmail("a@b")).thenReturn(Optional.of(new UserProfile()));
    assertTrue(service.findByEmail("a@b").isPresent());
  }

  @Test
  void updateDisplayNameSaves() {
    UserProfile existing = new UserProfile();
    existing.setDisplayName("old");
    when(repository.findById(2L)).thenReturn(Optional.of(existing));
    when(repository.save(any())).thenAnswer(i -> i.getArgument(0));
    Optional<UserProfile> updated = service.updateDisplayName(2L, "new");
    assertTrue(updated.isPresent());
    assertEquals("new", updated.get().getDisplayName());
  }

  @Test
  void deleteByIdDelegates() {
    doNothing().when(repository).deleteById(5L);
    service.deleteById(5L);
    verify(repository).deleteById(5L);
  }
}
