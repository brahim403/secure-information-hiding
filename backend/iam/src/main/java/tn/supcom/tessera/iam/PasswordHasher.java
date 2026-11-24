package tn.supcom.tessera.iam;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Double hashing (SEC-IA-01, AC-06):
 * <ul>
 *   <li><b>client</b>: SHA3-224 over {@code username:password@static-salt} (reference
 *       implementation; in production this runs in the browser so the raw password
 *       never reaches the server);</li>
 *   <li><b>server</b>: Argon2id over the client hash with a unique 16-byte salt,
 *       m = 19 MiB, t = 2, p = 1.</li>
 * </ul>
 * Verification is constant-time and {@link #dummyVerify} equalises timing for
 * unknown accounts so account existence cannot be inferred.
 */
public final class PasswordHasher {

    public static final int MEMORY_KIB = 19_456; // 19 MiB
    public static final int ITERATIONS = 2;
    public static final int PARALLELISM = 1;
    public static final int HASH_LENGTH = 32;
    private static final int SALT_LENGTH = 16;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getDecoder();
    private static final byte[] DUMMY_SALT = new byte[SALT_LENGTH];

    private PasswordHasher() {
    }

    /** Client-side pre-hash (reference). */
    public static String clientPreHash(String username, String password, String staticSalt) {
        try {
            byte[] d = MessageDigest.getInstance("SHA3-224")
                    .digest((username + ":" + password + "@" + staticSalt).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Argon2id hash in PHC-like string form (store this). */
    public static String hash(String clientHashHex) {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        byte[] raw = argon2(Argon2Parameters.ARGON2_id, clientHashHex.getBytes(StandardCharsets.UTF_8), salt);
        return "$argon2id$v=19$m=" + MEMORY_KIB + ",t=" + ITERATIONS + ",p=" + PARALLELISM
                + "$" + B64.encodeToString(salt) + "$" + B64.encodeToString(raw);
    }

    public static boolean verify(String clientHashHex, String stored) {
        String[] parts = stored.split("\\$");
        // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
        if (parts.length != 6) {
            return false;
        }
        byte[] salt = B64D.decode(parts[4]);
        byte[] expected = B64D.decode(parts[5]);
        byte[] actual = argon2(Argon2Parameters.ARGON2_id,
                clientHashHex.getBytes(StandardCharsets.UTF_8), salt);
        return MessageDigest.isEqual(expected, actual);
    }

    /** Runs an Argon2id pass to equalise timing when the account does not exist. */
    public static void dummyVerify(String clientHashHex) {
        argon2(Argon2Parameters.ARGON2_id, clientHashHex.getBytes(StandardCharsets.UTF_8), DUMMY_SALT);
    }

    /** Exposed for the i/d/id benchmark; {@code type} = Argon2Parameters.ARGON2_i/_d/_id. */
    public static byte[] argon2(int type, byte[] input, byte[] salt) {
        Argon2Parameters params = new Argon2Parameters.Builder(type)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(MEMORY_KIB)
                .withIterations(ITERATIONS)
                .withParallelism(PARALLELISM)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[HASH_LENGTH];
        gen.generateBytes(input, out);
        return out;
    }
}
