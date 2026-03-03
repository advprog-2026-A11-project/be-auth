package id.ac.ui.cs.advprog.auth.model;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "users")
public class UserProfile {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(unique = true, nullable = false)
  private String username;

  @Column(unique = true, nullable = false)
  private String email;

  @Column(unique = true)
  private String supabaseUserId;

  private String displayName;

  @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
  private String passwordHash;

  private String role;

  @JsonProperty("isActive")
  @JsonAlias("active")
  @Column(name = "is_active", nullable = false)
  private boolean active = true;

  @CreationTimestamp
  private LocalDateTime createdAt;

  @UpdateTimestamp
  private LocalDateTime updatedAt;

  public UserProfile() {
  }

  public UserProfile(
      String username,
      String email,
      String displayName,
      String passwordHash,
      String role,
      boolean isActive) {
    this.username = username;
    this.email = email;
    this.displayName = displayName;
    this.passwordHash = passwordHash;
    this.role = role;
    this.active = isActive;
  }

  public UserProfile(
      String username,
      String email,
      String supabaseUserId,
      String displayName,
      String passwordHash,
      String role,
      boolean isActive) {
    this.username = username;
    this.email = email;
    this.supabaseUserId = supabaseUserId;
    this.displayName = displayName;
    this.passwordHash = passwordHash;
    this.role = role;
    this.active = isActive;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

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

  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  public String getSupabaseUserId() {
    return supabaseUserId;
  }

  public void setSupabaseUserId(String supabaseUserId) {
    this.supabaseUserId = supabaseUserId;
  }

  public String getPasswordHash() {
    return passwordHash;
  }

  public void setPasswordHash(String passwordHash) {
    this.passwordHash = passwordHash;
  }

  public String getRole() {
    return role;
  }

  public void setRole(String role) {
    this.role = role;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public LocalDateTime getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(LocalDateTime createdAt) {
    this.createdAt = createdAt;
  }

  public LocalDateTime getUpdatedAt() {
    return updatedAt;
  }

  public void setUpdatedAt(LocalDateTime updatedAt) {
    this.updatedAt = updatedAt;
  }
}
