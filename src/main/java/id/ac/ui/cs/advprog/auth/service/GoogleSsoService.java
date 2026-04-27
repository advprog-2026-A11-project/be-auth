package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.dto.auth.AuthRequests.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.AuthResponses.SsoUrlResponse;

public interface GoogleSsoService {
  SsoUrlResponse createSsoUrl();

  default SsoUrlResponse createSsoUrl(String redirectTo) {
    return createSsoUrl();
  }

  SsoCallbackResponse handleCallback(SsoCallbackRequest request);
}
