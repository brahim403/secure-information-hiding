package tn.supcom.tessera.api.boundary;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import tn.supcom.tessera.api.control.IssuanceService;
import tn.supcom.tessera.api.domain.Ticket;

import java.util.Base64;

/**
 * Ticket issuance endpoint. Restricted to organizers; produces a signed,
 * opaque-id ticket server-side.
 */
@Path("/tickets")
public class IssuanceResource {

    @Inject
    IssuanceService issuanceService;

    @POST
    @RolesAllowed("ORGANIZER")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public IssueResponse issue(IssueRequest request) {
        Ticket ticket = issuanceService.issue(
                request.ownerId(), request.eventId(), request.gate(), request.seat(), request.slot());
        return new IssueResponse(
                ticket.id(),
                ticket.status().name(),
                Base64.getEncoder().encodeToString(ticket.signature()),
                ticket.kid());
    }
}
