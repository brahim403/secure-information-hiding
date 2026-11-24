package tn.supcom.tessera.api.control;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import tn.supcom.tessera.iam.LoginThrottle;
import tn.supcom.tessera.iam.PasswordHasher;
import tn.supcom.tessera.iam.Pkce;
import tn.supcom.tessera.iam.RefreshTokenService;
import tn.supcom.tessera.iam.SigningKeyRing;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Identity service: authenticates users (PKCE + Argon2id), issues short-lived
 * PASETO v4.public access tokens plus a rotating refresh token, and validates
 * presented access tokens. A demo user set is seeded in memory; a real identity
 * store replaces it later.
 */
@ApplicationScoped
public class IamService {

    public static final String STATIC_SALT = "tessera-client-salt";
    private static final long ACCESS_TTL_SECONDS = 300;

    private final SigningKeyRing keyRing = new SigningKeyRing();
    private final RefreshTokenService refreshTokens = new RefreshTokenService();
    private final LoginThrottle throttle = new LoginThrottle();
    private final Map<String, User> users = new ConcurrentHashMap<>();

    private record User(String username, String argon2, String role) {
    }

    public record AuthResult(String accessToken, String refreshToken, long expiresIn) {
    }

    public record Principal(String subject, String role) {
    }

    @PostConstruct
    void seedDemoUsers() {
        addUser("organizer-1", "Passw0rd!ChangeMe", "ORGANIZER");
        addUser("agent-1", "Passw0rd!ChangeMe", "AGENT");
    }

    private void addUser(String username, String password, String role) {
        String clientHash = PasswordHasher.clientPreHash(username, password, STATIC_SALT);
        users.put(username, new User(username, PasswordHasher.hash(clientHash), role));
    }

    /** OAuth 2.1 + PKCE token issuance. Throws {@link SecurityException} on any failure (uniform). */
    public AuthResult authenticate(String username, String clientHash, String verifier, String challenge) {
        if (!Pkce.verify(verifier, challenge)) {
            throw new SecurityException("invalid PKCE");
        }
        if (throttle.isLocked(username)) {
            throw new SecurityException("temporarily locked");
        }
        User user = users.get(username);
        boolean ok;
        if (user == null) {
            PasswordHasher.dummyVerify(clientHash); // constant-time: hide account existence
            ok = false;
        } else {
            ok = PasswordHasher.verify(clientHash, user.argon2());
        }
        if (!ok) {
            throttle.recordFailure(username);
            throw new SecurityException("invalid credentials");
        }
        throttle.reset(username);

        long exp = Instant.now().getEpochSecond() + ACCESS_TTL_SECONDS;
        String payload = "{\"sub\":\"" + username + "\",\"role\":\"" + user.role() + "\",\"exp\":" + exp + "}";
        String accessToken = tn.supcom.tessera.iam.PasetoV4Public.sign(
                payload.getBytes(StandardCharsets.UTF_8), keyRing.current().getPrivate(), new byte[0]);
        RefreshTokenService.Issued refresh = refreshTokens.issueNewFamily(username);
        return new AuthResult(accessToken, refresh.token(), ACCESS_TTL_SECONDS);
    }

    /** Validates a PASETO access token and returns the caller principal, if valid and unexpired. */
    public Optional<Principal> validate(String accessToken) {
        return keyRing.verify(accessToken).flatMap(payload -> {
            JsonObject claims = Json.createReader(new ByteArrayInputStream(payload)).readObject();
            if (claims.getJsonNumber("exp").longValue() < Instant.now().getEpochSecond()) {
                return Optional.empty();
            }
            return Optional.of(new Principal(claims.getString("sub"), claims.getString("role")));
        });
    }

    public String jwks() {
        return keyRing.jwks();
    }
}
