package tn.supcom.tessera.api.control;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import tn.supcom.tessera.api.domain.AdmissionResult;

/**
 * Verifies and consumes a ticket. The decision is taken entirely server-side and
 * the consumption is atomic, so a captured/duplicated ticket can be admitted at
 * most once even under concurrent scans (SEC-NR-02, SEC-RD-01, AC-02/AC-10).
 */
@ApplicationScoped
public class ScanService {

    @Inject
    TicketRepository repository;

    ScanService() {
        // for CDI proxying
    }

    public ScanService(TicketRepository repository) {
        this.repository = repository;
    }

    public AdmissionResult scan(String ticketId) {
        return repository.find(ticketId)
                .map(t -> t.consume() ? AdmissionResult.ADMITTED : AdmissionResult.DENIED)
                .orElse(AdmissionResult.DENIED);
    }
}
