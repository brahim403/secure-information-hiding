package tn.supcom.tessera.iam;

import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Phase C — Authentication primitives (SEC-IA-*, AC-05/AC-06). */
class IamPrimitivesTest {

    // ---- PKCE ----------------------------------------------------------------

    @Test
    void pkce_challenge_matches_only_the_right_verifier() {
        String verifier = Pkce.createVerifier();
        String challenge = Pkce.challengeFor(verifier);
        assertTrue(Pkce.verify(verifier, challenge));
        assertFalse(Pkce.verify(Pkce.createVerifier(), challenge));
    }

    // ---- Double hashing: SHA3-224 + Argon2id --------------------------------

    @Test
    void password_hash_verifies_and_rejects_wrong_password() {
        String ch = PasswordHasher.clientPreHash("buyer-1", "correct horse battery", "tessera-salt");
        String stored = PasswordHasher.hash(ch);
        assertTrue(PasswordHasher.verify(ch, stored));
        String wrong = PasswordHasher.clientPreHash("buyer-1", "wrong password", "tessera-salt");
        assertFalse(PasswordHasher.verify(wrong, stored));
    }

    @Test
    void argon2_i_d_id_benchmark_all_produce_32_bytes() {
        byte[] input = "client-hash".getBytes(StandardCharsets.UTF_8);
        byte[] salt = new byte[16];
        for (int t : new int[]{Argon2Parameters.ARGON2_i, Argon2Parameters.ARGON2_d, Argon2Parameters.ARGON2_id}) {
            long start = System.nanoTime();
            byte[] out = PasswordHasher.argon2(t, input, salt);
            long ms = (System.nanoTime() - start) / 1_000_000;
            String name = t == Argon2Parameters.ARGON2_i ? "i" : t == Argon2Parameters.ARGON2_d ? "d" : "id";
            System.out.printf("[argon2-bench] variant=%-2s m=19MiB t=2 p=1 -> %d bytes in %d ms%n",
                    name, out.length, ms);
            assertEquals(PasswordHasher.HASH_LENGTH, out.length);
        }
        // Chosen variant: id (hybrid) — data-independent first pass (side-channel
        // resistance) then data-dependent (GPU/TMTO resistance).
    }

    // ---- PASETO v4.public + JWK rotation ------------------------------------

    @Test
    void paseto_round_trips_and_rejects_tamper() {
        KeyPair kp = tn.supcom.tessera.proof.Ed25519Signatures.generateKeyPair();
        byte[] payload = "{\"sub\":\"buyer-1\",\"role\":\"BUYER\"}".getBytes(StandardCharsets.UTF_8);
        String token = PasetoV4Public.sign(payload, kp.getPrivate(), new byte[0]);
        assertTrue(token.startsWith("v4.public."));
        assertEquals(new String(payload), new String(PasetoV4Public.verify(token, kp.getPublic()).orElseThrow()));

        String tampered = token.substring(0, token.length() - 2) + (token.endsWith("A") ? "B" : "A");
        assertTrue(PasetoV4Public.verify(tampered, kp.getPublic()).isEmpty());

        KeyPair other = tn.supcom.tessera.proof.Ed25519Signatures.generateKeyPair();
        assertTrue(PasetoV4Public.verify(token, other.getPublic()).isEmpty());
    }

    @Test
    void keyring_verifies_across_rotation_and_publishes_jwks() {
        SigningKeyRing ring = new SigningKeyRing();
        String kid1 = ring.currentKid();
        byte[] payload = "{\"sub\":\"a\"}".getBytes(StandardCharsets.UTF_8);
        String oldToken = PasetoV4Public.sign(payload, ring.current().getPrivate(), new byte[0]);

        String kid2 = ring.rotate();
        assertNotEquals(kid1, kid2);
        // token from the previous (still active) key still verifies during overlap
        assertTrue(ring.verify(oldToken).isPresent());
        // new token from the current key verifies too
        String newToken = PasetoV4Public.sign(payload, ring.current().getPrivate(), new byte[0]);
        assertTrue(ring.verify(newToken).isPresent());

        assertTrue(ring.jwks().contains("\"kid\":\"" + kid1 + "\""));
        assertTrue(ring.jwks().contains("\"kid\":\"" + kid2 + "\""));
        assertTrue(ring.jwks().contains("\"crv\":\"Ed25519\""));

        ring.retire(kid1);
        assertTrue(ring.verify(oldToken).isEmpty(), "retired key must stop verifying");
    }

    // ---- Refresh-token rotation + reuse detection (sidejacking) --------------

    @Test
    void refresh_rotation_and_reuse_detection_revokes_family() {
        RefreshTokenService svc = new RefreshTokenService();
        RefreshTokenService.Issued first = svc.issueNewFamily("buyer-1");
        RefreshTokenService.Issued second = svc.rotate(first.token());   // normal rotation
        assertNotEquals(first.token(), second.token());

        // Attacker replays the already-rotated first token -> whole family revoked.
        assertThrows(RefreshTokenService.ReuseDetectedException.class, () -> svc.rotate(first.token()));
        assertTrue(svc.isFamilyRevoked(first.family()));
        // The legitimate (second) token is now useless too.
        assertThrows(IllegalArgumentException.class, () -> svc.rotate(second.token()));
    }

    // ---- TOTP ----------------------------------------------------------------

    @Test
    void totp_accepts_current_code_and_rejects_wrong() {
        byte[] secret = Totp.generateSecret();
        long now = 1_700_000_000L;
        String code = Totp.codeAt(secret, now);
        assertTrue(Totp.verify(secret, code, now, 1));
        assertFalse(Totp.verify(secret, "000000".equals(code) ? "111111" : "000000", now, 1));
        // far outside the window
        assertFalse(Totp.verify(secret, code, now + 3600, 1));
    }

    // ---- Progressive lockout -------------------------------------------------

    @Test
    void lockout_triggers_after_threshold() {
        AtomicLong clock = new AtomicLong(0);
        LoginThrottle throttle = new LoginThrottle(clock::get);
        for (int i = 0; i < LoginThrottle.THRESHOLD; i++) {
            assertFalse(throttle.isLocked("buyer-1"));
            throttle.recordFailure("buyer-1");
        }
        assertTrue(throttle.isLocked("buyer-1"));
        clock.addAndGet(LoginThrottle.BASE_LOCK_MS + 1);
        assertFalse(throttle.isLocked("buyer-1"));
    }

    // ---- ALTCHA proof of work ------------------------------------------------

    @Test
    void altcha_solution_verifies() {
        Altcha.Challenge c = Altcha.create(5000);
        long n = Altcha.solve(c);
        assertTrue(Altcha.verify(c.salt(), n, c.challengeHash(), c.maxNumber()));
        assertFalse(Altcha.verify(c.salt(), n + 1, c.challengeHash(), c.maxNumber()));
    }
}
