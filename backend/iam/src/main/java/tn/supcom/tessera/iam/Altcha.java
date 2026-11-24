package tn.supcom.tessera.iam;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * ALTCHA-style proof-of-work challenge (availability / anti-automation, SEC-IA-09).
 * The server reveals a salt and the SHA-256 of a hidden number ≤ {@code maxNumber};
 * the client must brute-force the number and return it. Verification is a single
 * hash — cheap for the server, costly for a bot at scale.
 */
public final class Altcha {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    public record Challenge(String salt, String challengeHash, long maxNumber) {
    }

    private Altcha() {
    }

    public static Challenge create(long maxNumber) {
        byte[] saltBytes = new byte[16];
        RANDOM.nextBytes(saltBytes);
        String salt = B64.encodeToString(saltBytes);
        long secret = (RANDOM.nextLong() & Long.MAX_VALUE) % (maxNumber + 1);
        return new Challenge(salt, hash(salt, secret), maxNumber);
    }

    /** Client side: find the number whose hash matches (brute force). */
    public static long solve(Challenge challenge) {
        for (long n = 0; n <= challenge.maxNumber(); n++) {
            if (hash(challenge.salt(), n).equals(challenge.challengeHash())) {
                return n;
            }
        }
        throw new IllegalStateException("unsolvable challenge");
    }

    public static boolean verify(String salt, long number, String expectedHash, long maxNumber) {
        if (number < 0 || number > maxNumber) {
            return false;
        }
        return MessageDigest.isEqual(
                hash(salt, number).getBytes(StandardCharsets.US_ASCII),
                expectedHash.getBytes(StandardCharsets.US_ASCII));
    }

    private static String hash(String salt, long number) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256")
                    .digest((salt + ":" + number).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
