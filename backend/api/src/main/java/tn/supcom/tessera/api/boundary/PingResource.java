package tn.supcom.tessera.api.boundary;

import jakarta.annotation.security.PermitAll;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * Liveness endpoint. Also anchors the REST security
 * architecture test.
 *
 * <p>Every JAX-RS method must carry an explicit access-control annotation
 * ({@code @RolesAllowed} / {@code @PermitAll} / {@code @DenyAll}); here the
 * ping is intentionally public.</p>
 */
@Path("/ping")
public class PingResource {

    @GET
    @PermitAll
    @Produces(MediaType.TEXT_PLAIN)
    public String ping() {
        return "pong";
    }
}
