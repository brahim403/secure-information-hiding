package tn.supcom.tessera.api.boundary;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import tn.supcom.tessera.api.control.ScanService;
import tn.supcom.tessera.api.domain.AdmissionResult;

/**
 * Scan / verification-and-consume endpoint. Restricted to gate agents. The
 * server decides and consumes atomically; a second presentation of the same
 * ticket is denied.
 */
@Path("/scan")
public class ScanResource {

    @Inject
    ScanService scanService;

    @POST
    @Path("/{id}")
    @RolesAllowed("AGENT")
    @Produces(MediaType.APPLICATION_JSON)
    public ScanResponse scan(@PathParam("id") String id) {
        AdmissionResult result = scanService.scan(id);
        return new ScanResponse(id, result.name());
    }
}
