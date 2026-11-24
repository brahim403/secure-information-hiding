package tn.supcom.tessera.proof;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES-256-GCM authenticated encryption for data at rest (SEC-DC-02).
 *
 * <p>Each message gets a fresh random 96-bit nonce ({@link SecureRandom}); the
 * output is {@code nonce || ciphertext||tag}. Additional authenticated data
 * (AAD) binds the ciphertext to the object identifier, so a blob cannot be
 * replayed against a different object. Decryption fails closed (throws) on any
 * tampering of ciphertext, tag or AAD.</p>
 */
public final class AesGcm {

    private static final int NONCE_BYTES = 12;   // 96-bit nonce, as recommended for GCM
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcm() {
    }

    public static SecretKey generateKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return kg.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES key generation failed", e);
        }
    }

    /** Returns {@code nonce(12) || ciphertext+tag}. */
    public static byte[] encrypt(SecretKey key, byte[] plaintext, byte[] aad) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(nonce.length + ciphertext.length)
                    .put(nonce).put(ciphertext).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("encryption failed", e);
        }
    }

    /** Fails closed: throws {@link GeneralSecurityException} if authentication fails. */
    public static byte[] decrypt(SecretKey key, byte[] blob, byte[] aad) throws GeneralSecurityException {
        if (blob.length < NONCE_BYTES) {
            throw new GeneralSecurityException("ciphertext too short");
        }
        byte[] nonce = new byte[NONCE_BYTES];
        System.arraycopy(blob, 0, nonce, 0, NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(blob, NONCE_BYTES, blob.length - NONCE_BYTES);
    }
}
