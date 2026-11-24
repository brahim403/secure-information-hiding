package tn.supcom.tessera.proof;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** C-I-D crypto core tests, incl. the required negative tests (SEC-DC-01/02, SEC-NR-01). */
class ProofTest {

    private static TicketClaims sampleClaims() {
        return new TicketClaims("tkt-001", "evt-42", "GATE-B", "A-12", "2026-12-01T20:00Z/21:00Z", 1, "k1");
    }

    // ---- Ed25519 (SEC-DC-01) -------------------------------------------------

    @Test
    void ed25519_signs_and_verifies() {
        KeyPair kp = Ed25519Signatures.generateKeyPair();
        byte[] msg = sampleClaims().canonicalBytes();
        byte[] sig = Ed25519Signatures.sign(kp.getPrivate(), msg);
        assertTrue(Ed25519Signatures.verify(kp.getPublic(), msg, sig));
    }

    @Test
    void ed25519_rejects_one_byte_tamper_of_signed_claims() {
        KeyPair kp = Ed25519Signatures.generateKeyPair();
        byte[] msg = sampleClaims().canonicalBytes();
        byte[] sig = Ed25519Signatures.sign(kp.getPrivate(), msg);

        byte[] tampered = msg.clone();
        tampered[tampered.length / 2] ^= 0x01; // flip a single bit
        assertFalse(Ed25519Signatures.verify(kp.getPublic(), tampered, sig));

        byte[] badSig = sig.clone();
        badSig[0] ^= 0x01;
        assertFalse(Ed25519Signatures.verify(kp.getPublic(), msg, badSig));
    }

    @Test
    void ed25519_rejects_wrong_key() {
        KeyPair signer = Ed25519Signatures.generateKeyPair();
        KeyPair other = Ed25519Signatures.generateKeyPair();
        byte[] msg = sampleClaims().canonicalBytes();
        byte[] sig = Ed25519Signatures.sign(signer.getPrivate(), msg);
        assertFalse(Ed25519Signatures.verify(other.getPublic(), msg, sig));
    }

    // ---- AES-256-GCM (SEC-DC-02) --------------------------------------------

    @Test
    void aesgcm_round_trips_with_aad() throws Exception {
        SecretKey key = AesGcm.generateKey();
        byte[] aad = "tkt-001".getBytes();
        byte[] pt = "sealed access payload".getBytes();
        byte[] blob = AesGcm.encrypt(key, pt, aad);
        assertArrayEquals(pt, AesGcm.decrypt(key, blob, aad));
    }

    @Test
    void aesgcm_fails_closed_on_tampered_ciphertext() {
        SecretKey key = AesGcm.generateKey();
        byte[] aad = "tkt-001".getBytes();
        byte[] blob = AesGcm.encrypt(key, "payload".getBytes(), aad);
        blob[blob.length - 1] ^= 0x01; // flip a bit in the tag
        assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(key, blob, aad));
    }

    @Test
    void aesgcm_fails_closed_on_wrong_aad() {
        SecretKey key = AesGcm.generateKey();
        byte[] blob = AesGcm.encrypt(key, "payload".getBytes(), "tkt-001".getBytes());
        assertThrows(GeneralSecurityException.class,
                () -> AesGcm.decrypt(key, blob, "tkt-999".getBytes()));
    }

    @Test
    void aesgcm_nonce_is_unique_over_100k_encryptions() {
        SecretKey key = AesGcm.generateKey();
        byte[] aad = "obj".getBytes();
        Set<String> nonces = new HashSet<>(1 << 18);
        for (int i = 0; i < 100_000; i++) {
            byte[] blob = AesGcm.encrypt(key, new byte[]{1, 2, 3}, aad);
            StringBuilder hex = new StringBuilder(24);
            for (int j = 0; j < 12; j++) {
                hex.append(Character.forDigit((blob[j] >> 4) & 0xF, 16));
                hex.append(Character.forDigit(blob[j] & 0xF, 16));
            }
            nonces.add(hex.toString());
        }
        assertEquals(100_000, nonces.size(), "nonce collision detected");
    }

    // ---- Canonical JSON (SEC-DC-01) -----------------------------------------

    @Test
    void canonical_json_is_order_independent() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("b", 2L);
        a.put("a", "x");
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("a", "x");
        b.put("b", 2L);
        assertEquals(CanonicalJson.canonicalize(a), CanonicalJson.canonicalize(b));
        assertEquals("{\"a\":\"x\",\"b\":2}", CanonicalJson.canonicalize(a));
    }

    @Test
    void canonical_json_changes_when_a_field_changes() {
        byte[] base = sampleClaims().canonicalBytes();
        TicketClaims moved = new TicketClaims(
                "tkt-001", "evt-42", "GATE-C", "A-12", "2026-12-01T20:00Z/21:00Z", 1, "k1");
        assertFalse(java.util.Arrays.equals(base, moved.canonicalBytes()));
    }
}
