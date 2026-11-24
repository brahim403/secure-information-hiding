package tn.supcom.tessera.api.control;

import jakarta.enterprise.context.ApplicationScoped;
import tn.supcom.tessera.api.domain.Ticket;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory ticket store (replaced by JPA/PostgreSQL in production).
 * Object-level access goes through {@link #findForHolder}, which enforces
 * ownership in the lookup itself — the anti-BOLA/IDOR control (SEC-AZ-02).
 */
@ApplicationScoped
public class TicketRepository {

    private final ConcurrentMap<String, Ticket> byId = new ConcurrentHashMap<>();

    public void save(Ticket ticket) {
        byId.put(ticket.id(), ticket);
    }

    public Optional<Ticket> find(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    /** Returns the ticket only when it belongs to {@code holderId}; empty otherwise (uniform 404). */
    public Optional<Ticket> findForHolder(String id, String holderId) {
        Ticket t = byId.get(id);
        return (t != null && t.ownerId().equals(holderId)) ? Optional.of(t) : Optional.empty();
    }
}
