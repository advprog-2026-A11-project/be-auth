package id.ac.ui.cs.advprog.auth.dto.auth;

import java.time.Instant;
import java.util.List;

public record AuthMeResponse(
    String sub,
    String email,
    String role,
    List<String> aud,
    String iss,
    Instant exp,
    ProfileSummary profile) {
}
