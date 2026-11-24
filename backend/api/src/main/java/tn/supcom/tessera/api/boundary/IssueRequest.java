package tn.supcom.tessera.api.boundary;

/** Issuance request DTO. */
public record IssueRequest(
        String ownerId,
        String eventId,
        String gate,
        String seat,
        String slot) {
}
