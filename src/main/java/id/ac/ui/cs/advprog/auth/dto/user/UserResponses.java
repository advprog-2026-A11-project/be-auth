package id.ac.ui.cs.advprog.auth.dto.user;

import id.ac.ui.cs.advprog.auth.model.UserProfile;
import java.util.List;
import java.util.UUID;

public final class UserResponses {

  private UserResponses() {
  }

  public record DeleteAccountResponse(
      String message,
      UUID userId) {
  }

  public record UpdateEmailResponse(
      String message,
      UUID userId,
      String email) {
  }

  public record UpdatePhoneResponse(
      String message,
      UUID userId,
      String phone) {
  }

  public record UpdateProfileResponse(
      String message,
      UUID userId,
      String username,
      String displayName,
      String email) {
  }

  public record PublicUserProfileResponse(
      UUID id,
      String username,
      String displayName) {

    public static PublicUserProfileResponse from(UserProfile profile) {
      return new PublicUserProfileResponse(
          profile.getId(),
          profile.getUsername(),
          profile.getDisplayName());
    }
  }

  public record LookupProfilesResponse(
      List<PublicUserProfileResponse> profiles) {
  }
}

