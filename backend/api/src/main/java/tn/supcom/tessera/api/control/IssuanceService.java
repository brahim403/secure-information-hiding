package tn.supcom.tessera.api.control;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import tn.supcom.tessera.api.domain.Ticket;
import tn.supcom.tessera.proof.Ed25519Signatures;
import tn.supcom.tessera.proof.TicketClaims;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Issues tickets: generates an opaque id, builds canonical claims, signs them
 * with Ed25519 (SEC-DC-01, SEC-NR-01) and stores the ticket. The signing key is
 * held server-side only (a credential store replaces this in-memory key in production).
 */
@ApplicationScoped
public class IssuanceService {

    private static final String KID = "k1";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeyPair keyPair = Ed25519Signatures.generateKeyPair();

    @Inject
    TicketRepository repository;

    IssuanceService() {
        // for CDI proxying
    }

    public IssuanceService(TicketRepository repository) {
        this.repository = repository;
    }

    public Ticket issue(String ownerId, String eventId, String gate, String seat, String slot) {
        String id = opaqueId();
        TicketClaims claims = new TicketClaims(id, eventId, gate, seat, slot, 1, KID);
        byte[] signature = Ed25519Signatures.sign(keyPair.getPrivate(), claims.canonicalBytes());
        Ticket ticket = new Ticket(id, ownerId, KID, claims, signature);
        repository.save(ticket);
        return ticket;
    }

    /** Public key so a third party can verify a ticket offline (non-repudiation). */
    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    private static String opaqueId() {
        byte[] bytes = new byte[16]; // 128-bit opaque, no personal data
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
