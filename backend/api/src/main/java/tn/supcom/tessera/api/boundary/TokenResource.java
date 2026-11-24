package tn.supcom.tessera.api.boundary;

import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import tn.supcom.tessera.api.control.IamService;
import tn.supcom.tessera.iam.PasswordHasher;

/**
 * OAuth 2.1 token endpoint (Authorization Code + PKCE). Returns a short-lived
 * PASETO access token and sets a hardened refresh cookie
 * ({@code HttpOnly; Secure; SameSite=Strict}).
 */
@Path("/iam/token")
public class TokenResource {

    @Inject
    IamService iamService;

    @POST
    @PermitAll
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(TokenRequest request) {
        try {
            String clientHash = PasswordHasher.clientPreHash(
                    request.username(), request.password(), IamService.STATIC_SALT);
            IamService.AuthResult result = iamService.authenticate(
                    request.username(), clientHash, request.codeVerifier(), request.codeChallenge());

            NewCookie refreshCookie = new NewCookie.Builder("refresh_token")
                    .value(result.refreshToken())
                    .httpOnly(true)
                    .secure(true)
                    .sameSite(NewCookie.SameSite.STRICT)
                    .path("/iam")
                    .build();

            return Response.ok(new TokenResponse(result.accessToken(), "Bearer", result.expiresIn()))
                    .cookie(refreshCookie)
                    .build();
        } catch (SecurityException e) {
            // Uniform failure: no distinction between unknown user and bad password.
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
    }
}
