package tn.supcom.tessera.api.boundary;

import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import tn.supcom.tessera.api.control.IamService;

/** Publishes the active Ed25519 public keys as a JWK Set (for token verification / rotation). */
@Path("/iam/jwks")
public class JwksResource {

    @Inject
    IamService iamService;

    @GET
    @PermitAll
    @Produces(MediaType.APPLICATION_JSON)
    public String jwks() {
        return iamService.jwks();
    }
}
