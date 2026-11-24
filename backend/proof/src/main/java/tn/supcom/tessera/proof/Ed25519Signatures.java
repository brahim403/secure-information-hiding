package tn.supcom.tessera.proof;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Ed25519 signatures over canonical claim bytes, using the JCA provider built
 * into Java 25 (no third-party crypto). Implements the integrity / authenticity
 * guarantee behind SEC-DC-01 and SEC-NR-01.
 */
public final class Ed25519Signatures {

    private static final String ALGORITHM = "Ed25519";

    private Ed25519Signatures() {
    }

    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    public static byte[] sign(PrivateKey privateKey, byte[] message) {
        try {
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(privateKey);
            signer.update(message);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    /** Verifies the signature; returns {@code false} (never throws) on any mismatch. */
    public static boolean verify(PublicKey publicKey, byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (SignatureException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("verification failed", e);
        }
    }
}
