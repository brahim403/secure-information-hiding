package tn.supcom.tessera.iam;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * OAuth 2.1 PKCE (RFC 7636, S256). The client keeps a random {@code verifier}
 * and sends only {@code challenge = BASE64URL(SHA-256(verifier))}; the STS later
 * checks that the presented verifier reproduces the challenge. This blocks
 * authorization-code interception (AC-06).
 */
public final class Pkce {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private Pkce() {
    }

    public static String createVerifier() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return B64.encodeToString(bytes);
    }

    public static String challengeFor(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return B64.encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Constant-time check that the verifier matches the stored challenge. */
    public static boolean verify(String verifier, String challenge) {
        byte[] expected = challengeFor(verifier).getBytes(StandardCharsets.US_ASCII);
        byte[] actual = challenge.getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, actual);
    }
}
