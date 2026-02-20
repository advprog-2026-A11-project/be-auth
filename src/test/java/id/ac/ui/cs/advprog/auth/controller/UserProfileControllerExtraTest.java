package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

class UserProfileControllerExtraTest {

  @Mock
  private UserProfileService service;

  @InjectMocks
  private UserProfileController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void allReturnsList() {
    when(service.findAll()).thenReturn(List.of(new UserProfile(), new UserProfile()));
    var list = controller.all();
    assertEquals(2, list.size());
  }

  @Test
  void getByIdNotFound() {
    when(service.findById(123L)).thenReturn(Optional.empty());
    ResponseEntity<UserProfile> resp = controller.getById(123L);
    assertEquals(404, resp.getStatusCodeValue());
  }

  @Test
  void getByIdFound() {
    UserProfile u = new UserProfile();
    when(service.findById(5L)).thenReturn(Optional.of(u));
    ResponseEntity<UserProfile> resp = controller.getById(5L);
    assertEquals(200, resp.getStatusCodeValue());
  }

  @Test
  void updateNotFoundReturnsNotFound() {
    when(service.update(eq(10L), any())).thenReturn(Optional.empty());
    ResponseEntity<UserProfile> resp = controller.update(10L, new UserProfile());
    assertEquals(404, resp.getStatusCodeValue());
  }

  @Test
  void normalizeIntegrationDefaultsSetsDefaults() {
    UserProfile u = new UserProfile();
    u.setUsername(null);
    u.setDisplayName(null);
    u.setRole("");
    u.setEmail("");
    // call create to trigger normalizeIntegrationDefaults
    when(service.create(any())).thenAnswer(i -> i.getArgument(0));
    var resp = controller.create(u);
    assertEquals(201, resp.getStatusCodeValue());
    UserProfile created = resp.getBody();
    assertNotNull(created.getUsername());
    assertNotNull(created.getDisplayName());
    assertEquals("USER", created.getRole());
    assertTrue(created.getEmail().endsWith("@local.test"));
  }
}
