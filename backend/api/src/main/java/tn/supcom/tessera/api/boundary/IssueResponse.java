package tn.supcom.tessera.api.boundary;

/** Issued ticket DTO: opaque id, status, Ed25519 signature (base64) and key id. */
public record IssueResponse(
        String id,
        String status,
        String signatureBase64,
        String kid) {
}
