package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import id.ac.ui.cs.advprog.auth.dto.user.UserProfileRequest;
import id.ac.ui.cs.advprog.auth.dto.user.UserProfileResponse;
import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.security.CurrentUserProvider;
import id.ac.ui.cs.advprog.auth.service.AuthSessionService;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class UserProfileControllerTest {

  @Mock
  private UserProfileService service;

  @Mock
  private CurrentUserProvider currentUserProvider;

  @Mock
  private AuthSessionService authSessionService;

  @InjectMocks
  private UserProfileController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void createReturnsCreated() {
    final UserProfileRequest in = new UserProfileRequest();
    UserProfile created = new UserProfile();
    created.setRole("USER");
    created.setActive(true);
    when(service.create(any())).thenReturn(created);
    ResponseEntity<UserProfileResponse> resp = controller.create(in);
    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    assertNotNull(resp.getBody());
  }

  @Test
  void createMapsRequestAndPreservesProvidedFields() {
    UserProfileRequest in = new UserProfileRequest();
    in.setUsername("alice");
    in.setEmail("alice@example.com");
    in.setSupabaseUserId("sub-1");
    in.setDisplayName("Alice");
    in.setRole("ADMIN");
    in.setActive(false);

    when(service.create(any())).thenAnswer(invocation -> invocation.getArgument(0));
    ResponseEntity<UserProfileResponse> resp = controller.create(in);

    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
    UserProfileResponse body = resp.getBody();
    assertNotNull(body);
    assertEquals("alice", body.username());
    assertEquals("alice@example.com", body.email());
    assertEquals("sub-1", body.supabaseUserId());
    assertEquals("Alice", body.displayName());
    assertEquals("ADMIN", body.role());
    assertFalse(body.isActive());
  }

  @Test
  void updateDisplayNameMissingReturnsBadRequest() {
    Map<String, String> body = new HashMap<>();
    ResponseEntity<Object> resp = controller.updateDisplayName(1L, body);
    assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
  }

  @Test
  void updateDisplayNameSuccessReturnsOk() {
    Map<String, String> body = new HashMap<>();
    body.put("displayName", "bob");
    UserProfile u = new UserProfile();
    when(service.updateDisplayName(1L, "bob")).thenReturn(Optional.of(u));
    ResponseEntity<Object> resp = controller.updateDisplayName(1L, body);
    assertEquals(HttpStatus.OK, resp.getStatusCode());
  }

  @Test
  void updateDisplayNameNotFoundReturnsNotFound() {
    Map<String, String> body = new HashMap<>();
    body.put("displayName", "bob");

    when(service.updateDisplayName(100L, "bob")).thenReturn(Optional.empty());
    ResponseEntity<Object> resp = controller.updateDisplayName(100L, body);
    assertEquals(HttpStatus.NOT_FOUND, resp.getStatusCode());
  }

  @Test
  void updateReturnsOkWhenFound() {
    UserProfileRequest request = new UserProfileRequest();
    request.setUsername("newuser");
    request.setDisplayName("New User");
    request.setRole("ADMIN");
    request.setEmail("newuser@example.com");
    request.setActive(false);

    UserProfile updated = new UserProfile();
    updated.setUsername("newuser");
    updated.setDisplayName("New User");
    updated.setRole("ADMIN");
    updated.setEmail("newuser@example.com");
    updated.setActive(false);

    when(service.update(eq(10L), any())).thenReturn(Optional.of(updated));

    ResponseEntity<UserProfileResponse> resp = controller.update(10L, request);
    assertEquals(HttpStatus.OK, resp.getStatusCode());
    assertNotNull(resp.getBody());
    assertEquals("newuser", resp.getBody().username());
    assertEquals("newuser@example.com", resp.getBody().email());
    assertFalse(resp.getBody().isActive());
  }

  @Test
  void deleteReturnsNoContent() {
    ResponseEntity<Void> resp = controller.delete(2L);
    assertEquals(HttpStatus.NO_CONTENT, resp.getStatusCode());
    verify(service).deactivateById(2L);
  }
}
