package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;

public interface GoogleSsoService {
  SsoUrlResponse createSsoUrl();

  default SsoUrlResponse createSsoUrl(String redirectTo) {
    return createSsoUrl();
  }

  SsoCallbackResponse handleCallback(SsoCallbackRequest request);
}
