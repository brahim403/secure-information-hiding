package tn.supcom.tessera.api.boundary;

/**
 * Token request. {@code codeVerifier}/{@code codeChallenge} carry PKCE; the
 * password is pre-hashed client-side in production (done server-side here for the
 * demo flow).
 */
public record TokenRequest(
        String username,
        String password,
        String codeVerifier,
        String codeChallenge) {
}
