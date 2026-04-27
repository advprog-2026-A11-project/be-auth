package id.ac.ui.cs.advprog.auth.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "users")
public class UserProfile {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(unique = true, nullable = false)
  private String username;

  @Column(unique = true, nullable = false)
  private String email;

  @Column(unique = true)
  private String supabaseUserId;

  @Column(unique = true)
  private String phone;

  private String authProvider;

  @Column(unique = true)
  private String googleSub;

  private String displayName;

  private String role;

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
      String role,
      boolean isActive) {
    this.username = username;
    this.email = email;
    this.displayName = displayName;
    this.role = role;
    this.active = isActive;
  }

  public UserProfile(
      String username,
      String email,
      String supabaseUserId,
      String displayName,
      String role,
      boolean isActive) {
    this.username = username;
    this.email = email;
    this.supabaseUserId = supabaseUserId;
    this.displayName = displayName;
    this.role = role;
    this.active = isActive;
  }

  public UUID getId() {
    return id;
  }

  public void setId(UUID id) {
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

  public String getPhone() {
    return phone;
  }

  public void setPhone(String phone) {
    this.phone = phone;
  }

  public String getAuthProvider() {
    return authProvider;
  }

  public void setAuthProvider(String authProvider) {
    this.authProvider = authProvider;
  }

  public String getGoogleSub() {
    return googleSub;
  }

  public void setGoogleSub(String googleSub) {
    this.googleSub = googleSub;
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
