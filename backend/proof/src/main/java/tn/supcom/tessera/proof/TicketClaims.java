package tn.supcom.tessera.proof;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The canonical, signable claims of a ticket (SEC-DC-01). The format version and
 * key id ({@code kid}) are part of the signed fields so a forged or down-graded
 * claim set cannot verify.
 */
public record TicketClaims(
        String ticketId,
        String eventId,
        String gate,
        String seat,
        String slot,
        int formatVersion,
        String kid) {

    /** Canonical bytes to sign / verify (stable regardless of field insertion order). */
    public byte[] canonicalBytes() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ticketId", ticketId);
        m.put("eventId", eventId);
        m.put("gate", gate);
        m.put("seat", seat);
        m.put("slot", slot);
        m.put("formatVersion", (long) formatVersion);
        m.put("kid", kid);
        return CanonicalJson.canonicalize(m).getBytes(StandardCharsets.UTF_8);
    }
}
