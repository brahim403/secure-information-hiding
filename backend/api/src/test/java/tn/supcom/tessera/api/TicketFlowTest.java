package tn.supcom.tessera.api;

import org.junit.jupiter.api.Test;
import tn.supcom.tessera.api.control.IssuanceService;
import tn.supcom.tessera.api.control.ScanService;
import tn.supcom.tessera.api.control.TicketRepository;
import tn.supcom.tessera.api.domain.AdmissionResult;
import tn.supcom.tessera.api.domain.Ticket;
import tn.supcom.tessera.api.domain.TicketStatus;
import tn.supcom.tessera.proof.Ed25519Signatures;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Negative / attack tests for the ticketing core (AC-02, AC-04). */
class TicketFlowTest {

    private IssuanceService issuance;
    private ScanService scan;

    private Ticket freshTicket() {
        TicketRepository repo = new TicketRepository();
        issuance = new IssuanceService(repo);
        scan = new ScanService(repo);
        return issuance.issue("buyer-1", "evt-42", "GATE-B", "A-12", "slot-1");
    }

    @Test
    void hundred_concurrent_scans_admit_exactly_once() throws Exception {
        Ticket ticket = freshTicket();
        int threads = 100;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger admitted = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (scan.scan(ticket.id()) == AdmissionResult.ADMITTED) {
                        admitted.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(1, admitted.get(), "exactly one scan must be admitted");
        assertEquals(TicketStatus.CONSUMED, ticket.status());
    }

    @Test
    void second_scan_is_denied() {
        Ticket ticket = freshTicket();
        assertEquals(AdmissionResult.ADMITTED, scan.scan(ticket.id()));
        assertEquals(AdmissionResult.DENIED, scan.scan(ticket.id()));
    }

    @Test
    void idor_cross_user_lookup_returns_empty() {
        Ticket ticket = freshTicket();
        TicketRepository repo = new TicketRepository();
        repo.save(ticket);
        assertTrue(repo.findForHolder(ticket.id(), "buyer-1").isPresent());
        assertTrue(repo.findForHolder(ticket.id(), "attacker-9").isEmpty(),
                "another user must not reach this ticket (BOLA/IDOR)");
    }

    @Test
    void tampered_claims_fail_signature_verification() {
        Ticket ticket = freshTicket();
        byte[] signed = ticket.claims().canonicalBytes();
        assertTrue(Ed25519Signatures.verify(issuance.publicKey(), signed, ticket.signature()));

        byte[] tampered = signed.clone();
        tampered[tampered.length / 2] ^= 0x01;
        assertFalse(Ed25519Signatures.verify(issuance.publicKey(), tampered, ticket.signature()));
    }

    @Test
    void unknown_ticket_is_denied() {
        freshTicket();
        assertEquals(AdmissionResult.DENIED, scan.scan("does-not-exist"));
    }
}
