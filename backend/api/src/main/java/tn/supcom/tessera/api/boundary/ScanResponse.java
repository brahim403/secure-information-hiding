package tn.supcom.tessera.api.boundary;

/** Scan decision DTO (minimal, no personal data). */
public record ScanResponse(
        String ticketId,
        String decision) {
}
