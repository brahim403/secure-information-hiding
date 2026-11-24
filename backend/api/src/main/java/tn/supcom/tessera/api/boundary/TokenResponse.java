package tn.supcom.tessera.api.boundary;

/** OAuth-style token response (access token is a PASETO; refresh token is in a cookie). */
public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn) {
}
