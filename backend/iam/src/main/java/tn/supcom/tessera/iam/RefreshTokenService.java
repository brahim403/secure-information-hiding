package tn.supcom.tessera.iam;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Refresh-token rotation with reuse detection — the defence against refresh-token
 * sidejacking (the attack targets the refresh token, not the access token).
 *
 * <p>Each use rotates the token within its family. If a token that has already
 * been rotated is presented again (a sign it was stolen and replayed), the whole
 * family is revoked, logging out both the attacker and the victim.</p>
 */
public final class RefreshTokenService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private record Entry(String userId, String family, boolean used) {
    }

    private final Map<String, Entry> byTokenHash = new ConcurrentHashMap<>();
    private final Map<String, Boolean> revokedFamilies = new ConcurrentHashMap<>();

    public record Issued(String token, String family) {
    }

    public static final class ReuseDetectedException extends RuntimeException {
        public ReuseDetectedException(String family) {
            super("refresh-token reuse detected; family revoked: " + family);
        }
    }

    public Issued issueNewFamily(String userId) {
        String family = randomId();
        return issueIn(userId, family);
    }

    /** Rotates: consumes the presented token and returns a fresh one in the same family. */
    public synchronized Issued rotate(String presentedToken) {
        String hash = sha256(presentedToken);
        Entry entry = byTokenHash.get(hash);
        if (entry == null || Boolean.TRUE.equals(revokedFamilies.get(entry == null ? "" : entry.family()))) {
            throw new IllegalArgumentException("invalid or revoked refresh token");
        }
        if (entry.used()) {
            // Reuse of an already-rotated token => the family is compromised.
            revokedFamilies.put(entry.family(), Boolean.TRUE);
            throw new ReuseDetectedException(entry.family());
        }
        byTokenHash.put(hash, new Entry(entry.userId(), entry.family(), true));
        return issueIn(entry.userId(), entry.family());
    }

    public boolean isFamilyRevoked(String family) {
        return Boolean.TRUE.equals(revokedFamilies.get(family));
    }

    private Issued issueIn(String userId, String family) {
        byte[] secret = new byte[32];
        RANDOM.nextBytes(secret);
        String token = B64.encodeToString(secret);
        byTokenHash.put(sha256(token), new Entry(userId, family, false));
        return new Issued(token, family);
    }

    private static String randomId() {
        byte[] b = new byte[12];
        RANDOM.nextBytes(b);
        return B64.encodeToString(b);
    }

    private static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
