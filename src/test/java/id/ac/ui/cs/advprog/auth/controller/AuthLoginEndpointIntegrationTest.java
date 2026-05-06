package id.ac.ui.cs.advprog.auth.controller;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.LoginResponse;
import id.ac.ui.cs.advprog.auth.service.auth.AuthLoginService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AuthLoginEndpointIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private AuthLoginService authLoginService;

  @Test
  void loginWithPhoneIdentifierReturnsOk() throws Exception {
    when(authLoginService.login("0812-345-6789", "password123"))
        .thenReturn(new LoginResponse(
            "access-token",
            "refresh-token",
            "Bearer",
            3600L,
            "535251d5-a941-49b0-9a04-5b26dc55ec61",
            "STUDENT",
            "Login successful"));

    mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                """
                {
                  "identifier": "0812-345-6789",
                  "password": "password123"
                }
                """))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").value("access-token"))
        .andExpect(jsonPath("$.userId").value("535251d5-a941-49b0-9a04-5b26dc55ec61"))
        .andExpect(jsonPath("$.role").value("STUDENT"));
  }

  @Test
  void loginWithUnregisteredPhoneReturnsBadRequest() throws Exception {
    when(authLoginService.login("0811 1111 111", "password123"))
        .thenThrow(new IllegalArgumentException("phone number is not registered"));

    mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                """
                {
                  "identifier": "0811 1111 111",
                  "password": "password123"
                }
                """))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value("phone number is not registered"));
  }
}
