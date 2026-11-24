package tn.supcom.tessera.iam;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Time-based one-time password (RFC 6238, HMAC-SHA1, 6 digits, 30 s step) for the
 * mandatory second factor on privileged roles (SEC-IA-07). A verified code is
 * accepted once within its window; a small ± window absorbs clock skew.
 */
public final class Totp {

    private static final int DIGITS = 6;
    private static final long STEP_SECONDS = 30;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {
    }

    public static byte[] generateSecret() {
        byte[] secret = new byte[20];
        RANDOM.nextBytes(secret);
        return secret;
    }

    public static String codeAt(byte[] secret, long epochSeconds) {
        long counter = epochSeconds / STEP_SECONDS;
        byte[] msg = new byte[8];
        for (int i = 7; i >= 0; i--) {
            msg[i] = (byte) (counter & 0xFF);
            counter >>>= 8;
        }
        byte[] hash = hmacSha1(secret, msg);
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        int otp = binary % (int) Math.pow(10, DIGITS);
        return String.format("%0" + DIGITS + "d", otp);
    }

    /** Verifies within ±{@code window} steps (constant-time per candidate). */
    public static boolean verify(byte[] secret, String code, long epochSeconds, int window) {
        for (int w = -window; w <= window; w++) {
            String candidate = codeAt(secret, epochSeconds + w * STEP_SECONDS);
            if (constantTimeEquals(candidate, code)) {
                return true;
            }
        }
        return false;
    }

    private static byte[] hmacSha1(byte[] key, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac.doFinal(msg);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }
}
