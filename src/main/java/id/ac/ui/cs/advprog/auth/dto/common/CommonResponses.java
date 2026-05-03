package id.ac.ui.cs.advprog.auth.dto.common;

public final class CommonResponses {

  private CommonResponses() {
  }

  public record ErrorResponse(String error) {
  }
}

