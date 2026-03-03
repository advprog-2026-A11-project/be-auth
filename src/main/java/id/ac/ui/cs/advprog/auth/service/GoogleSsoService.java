package id.ac.ui.cs.advprog.auth.service;

import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackRequest;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoCallbackResponse;
import id.ac.ui.cs.advprog.auth.dto.auth.SsoUrlResponse;

public interface GoogleSsoService {
  SsoUrlResponse createSsoUrl();

  SsoCallbackResponse handleCallback(SsoCallbackRequest request);
}
