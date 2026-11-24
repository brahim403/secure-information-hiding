package tn.supcom.tessera.api.security;

import jakarta.annotation.Priority;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;
import tn.supcom.tessera.api.control.IamService;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Arrays;
import java.util.Optional;

/**
 * Enforces the access-control annotations against the PASETO bearer token
 * (SEC-AZ-01). {@code @PermitAll} passes through; {@code @DenyAll} is 403;
 * {@code @RolesAllowed} requires a valid token whose role is in the allowed set,
 * otherwise 401 (no/invalid token) or 403 (wrong role).
 */
@Provider
@Priority(Priorities.AUTHORIZATION)
public class AccessControlFilter implements ContainerRequestFilter {

    @Context
    ResourceInfo resourceInfo;

    @Inject
    IamService iamService;

    @Override
    public void filter(ContainerRequestContext ctx) {
        Method method = resourceInfo.getResourceMethod();
        if (method == null || method.isAnnotationPresent(PermitAll.class)) {
            return;
        }
        if (method.isAnnotationPresent(DenyAll.class)) {
            ctx.abortWith(Response.status(Response.Status.FORBIDDEN).build());
            return;
        }
        RolesAllowed rolesAllowed = method.getAnnotation(RolesAllowed.class);
        if (rolesAllowed == null) {
            rolesAllowed = resourceInfo.getResourceClass().getAnnotation(RolesAllowed.class);
        }
        if (rolesAllowed == null) {
            return; // no constraint declared (the architecture test prevents this in practice)
        }

        String token = bearerToken(ctx);
        Optional<IamService.Principal> principal =
                token == null ? Optional.empty() : iamService.validate(token);
        if (principal.isEmpty()) {
            ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            return;
        }
        String role = principal.get().role();
        if (Arrays.stream(rolesAllowed.value()).noneMatch(role::equals)) {
            ctx.abortWith(Response.status(Response.Status.FORBIDDEN).build());
            return;
        }
        ctx.setSecurityContext(securityContext(principal.get(), ctx.getUriInfo().getRequestUri().getScheme()));
    }

    private static String bearerToken(ContainerRequestContext ctx) {
        String header = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return header.substring(7).trim();
        }
        return null;
    }

    private static SecurityContext securityContext(IamService.Principal p, String scheme) {
        Principal principal = p::subject;
        return new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return principal;
            }

            @Override
            public boolean isUserInRole(String role) {
                return p.role().equals(role);
            }

            @Override
            public boolean isSecure() {
                return "https".equalsIgnoreCase(scheme);
            }

            @Override
            public String getAuthenticationScheme() {
                return "BEARER";
            }
        };
    }
}
