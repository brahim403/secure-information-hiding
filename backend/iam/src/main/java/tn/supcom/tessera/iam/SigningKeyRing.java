package tn.supcom.tessera.iam;

import tn.supcom.tessera.proof.Ed25519Signatures;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Ed25519 signing key ring with rotation and a published JWK set (SEC-DC-12).
 * Several keys stay active during an overlap window: new tokens are signed with
 * the current key, while tokens signed by a previous (still-active) key keep
 * verifying. The public keys are published as OKP/Ed25519 JWKs.
 */
public final class SigningKeyRing {

    private final Map<String, KeyPair> active = new LinkedHashMap<>();
    private String currentKid;
    private int counter;

    public SigningKeyRing() {
        rotate();
    }

    public synchronized String rotate() {
        String kid = "k" + (++counter);
        active.put(kid, Ed25519Signatures.generateKeyPair());
        currentKid = kid;
        return kid;
    }

    public synchronized String currentKid() {
        return currentKid;
    }

    public synchronized KeyPair current() {
        return active.get(currentKid);
    }

    public synchronized PublicKey publicKey(String kid) {
        KeyPair kp = active.get(kid);
        return kp == null ? null : kp.getPublic();
    }

    /** Verifies a PASETO against any currently-active key (rotation overlap). */
    public synchronized Optional<byte[]> verify(String token) {
        for (KeyPair kp : active.values()) {
            Optional<byte[]> payload = PasetoV4Public.verify(token, kp.getPublic());
            if (payload.isPresent()) {
                return payload;
            }
        }
        return Optional.empty();
    }

    /** Retire a key after the overlap window so it no longer verifies. */
    public synchronized void retire(String kid) {
        if (!kid.equals(currentKid)) {
            active.remove(kid);
        }
    }

    /** JWK Set of the active public keys (what a client fetches from /iam/jwks). */
    public synchronized String jwks() {
        List<String> keys = new ArrayList<>();
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        for (Map.Entry<String, KeyPair> e : active.entrySet()) {
            byte[] spki = e.getValue().getPublic().getEncoded();
            byte[] raw = Arrays.copyOfRange(spki, spki.length - 32, spki.length); // Ed25519 raw pub
            keys.add("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"sig\",\"kid\":\""
                    + e.getKey() + "\",\"x\":\"" + b64.encodeToString(raw) + "\"}");
        }
        return "{\"keys\":[" + String.join(",", keys) + "]}";
    }
}
