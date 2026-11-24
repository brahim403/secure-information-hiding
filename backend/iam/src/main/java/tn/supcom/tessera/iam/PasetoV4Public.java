package tn.supcom.tessera.iam;

import tn.supcom.tessera.proof.Ed25519Signatures;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

/**
 * PASETO v4.public tokens (Ed25519 / EdDSA) — used instead of JWT (AC-05/AC-06).
 * The payload is signed, not encrypted; the signature covers the header, payload,
 * footer and (empty) implicit assertion via PASETO's pre-authentication encoding.
 */
public final class PasetoV4Public {

    private static final String HEADER = "v4.public.";
    private static final byte[] HEADER_BYTES = HEADER.getBytes(StandardCharsets.UTF_8);
    private static final byte[] EMPTY = new byte[0];
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private PasetoV4Public() {
    }

    public static String sign(byte[] payload, PrivateKey signingKey, byte[] footer) {
        byte[] f = footer == null ? EMPTY : footer;
        byte[] m2 = pae(HEADER_BYTES, payload, f, EMPTY);
        byte[] sig = Ed25519Signatures.sign(signingKey, m2);
        byte[] body = concat(payload, sig);
        String token = HEADER + B64.encodeToString(body);
        if (f.length > 0) {
            token += "." + B64.encodeToString(f);
        }
        return token;
    }

    /** Returns the verified payload bytes, or empty if the token is invalid. */
    public static Optional<byte[]> verify(String token, PublicKey publicKey) {
        if (!token.startsWith(HEADER)) {
            return Optional.empty();
        }
        String rest = token.substring(HEADER.length());
        String[] parts = rest.split("\\.", 2);
        byte[] body;
        byte[] footer;
        try {
            body = B64D.decode(parts[0]);
            footer = parts.length == 2 ? B64D.decode(parts[1]) : EMPTY;
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (body.length < 64) {
            return Optional.empty();
        }
        byte[] payload = Arrays.copyOfRange(body, 0, body.length - 64);
        byte[] sig = Arrays.copyOfRange(body, body.length - 64, body.length);
        byte[] m2 = pae(HEADER_BYTES, payload, footer, EMPTY);
        return Ed25519Signatures.verify(publicKey, m2, sig) ? Optional.of(payload) : Optional.empty();
    }

    /** PASETO pre-authentication encoding: LE64(count) then LE64(len)||piece for each. */
    private static byte[] pae(byte[]... pieces) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(le64(pieces.length));
        for (byte[] piece : pieces) {
            out.writeBytes(le64(piece.length));
            out.writeBytes(piece);
        }
        return out.toByteArray();
    }

    private static byte[] le64(long n) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) {
            b[i] = (byte) (n & 0xFF);
            n >>>= 8;
        }
        b[7] &= 0x7F; // top bit cleared, per spec
        return b;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
