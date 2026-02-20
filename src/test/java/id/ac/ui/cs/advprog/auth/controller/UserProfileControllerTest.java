package id.ac.ui.cs.advprog.auth.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import id.ac.ui.cs.advprog.auth.service.UserProfileService;
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

  @InjectMocks
  private UserProfileController controller;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void createReturnsCreated() {
    UserProfile in = new UserProfile();
    when(service.create(any())).thenReturn(in);
    ResponseEntity<UserProfile> resp = controller.create(in);
    assertEquals(HttpStatus.CREATED, resp.getStatusCode());
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
  void deleteReturnsNoContent() {
    ResponseEntity<Void> resp = controller.delete(2L);
    assertEquals(HttpStatus.NO_CONTENT, resp.getStatusCode());
    verify(service).deleteById(2L);
  }
}
