package id.ac.ui.cs.advprog.auth.dto.user;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

public class UserProfileRequest {

  private String username;
  private String email;
  private String supabaseUserId;
  private String displayName;
  private String role;

  @JsonProperty("isActive")
  @JsonAlias("active")
  private Boolean active;

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getSupabaseUserId() {
    return supabaseUserId;
  }

  public void setSupabaseUserId(String supabaseUserId) {
    this.supabaseUserId = supabaseUserId;
  }

  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  public String getRole() {
    return role;
  }

  public void setRole(String role) {
    this.role = role;
  }

  public Boolean getActive() {
    return active;
  }

  public void setActive(Boolean active) {
    this.active = active;
  }
}

