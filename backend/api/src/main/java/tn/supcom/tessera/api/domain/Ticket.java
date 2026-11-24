package tn.supcom.tessera.api.domain;

import tn.supcom.tessera.proof.TicketClaims;

import java.util.concurrent.atomic.AtomicReference;

/**
 * A ticket: opaque id, owner, signed canonical claims, and a status that can
 * only be consumed once. The {@link #consume()} transition is an atomic
 * compare-and-set (ISSUED → CONSUMED), so under concurrency exactly one scan
 * wins (SEC-RD-01, anti-replay AC-02).
 */
public final class Ticket {

    private final String id;
    private final String ownerId;
    private final String kid;
    private final TicketClaims claims;
    private final byte[] signature;
    private final AtomicReference<TicketStatus> status = new AtomicReference<>(TicketStatus.ISSUED);

    public Ticket(String id, String ownerId, String kid, TicketClaims claims, byte[] signature) {
        this.id = id;
        this.ownerId = ownerId;
        this.kid = kid;
        this.claims = claims;
        this.signature = signature.clone();
    }

    /** Atomically consumes the ticket; returns true only for the single winning caller. */
    public boolean consume() {
        return status.compareAndSet(TicketStatus.ISSUED, TicketStatus.CONSUMED);
    }

    public String id() {
        return id;
    }

    public String ownerId() {
        return ownerId;
    }

    public String kid() {
        return kid;
    }

    public TicketClaims claims() {
        return claims;
    }

    public byte[] signature() {
        return signature.clone();
    }

    public TicketStatus status() {
        return status.get();
    }
}
