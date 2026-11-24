package tn.supcom.tessera.iam;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Progressive lockout against brute force / credential stuffing (SEC-IA-05).
 * After {@code THRESHOLD} failures the key (account or IP) is locked for a delay
 * that doubles with each further failure, capped at {@code MAX_LOCK_MS}.
 */
public final class LoginThrottle {

    public static final int THRESHOLD = 5;
    public static final long BASE_LOCK_MS = 60_000;      // 1 min
    public static final long MAX_LOCK_MS = 30 * 60_000;  // 30 min

    private record State(int failures, long lockedUntil) {
    }

    private final Map<String, State> states = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    public LoginThrottle() {
        this(System::currentTimeMillis);
    }

    public LoginThrottle(LongSupplier clock) {
        this.clock = clock;
    }

    public boolean isLocked(String key) {
        State s = states.get(key);
        return s != null && clock.getAsLong() < s.lockedUntil();
    }

    public synchronized void recordFailure(String key) {
        State s = states.getOrDefault(key, new State(0, 0));
        int failures = s.failures() + 1;
        long lockedUntil = 0;
        if (failures >= THRESHOLD) {
            long delay = Math.min(BASE_LOCK_MS << (failures - THRESHOLD), MAX_LOCK_MS);
            lockedUntil = clock.getAsLong() + delay;
        }
        states.put(key, new State(failures, lockedUntil));
    }

    public void reset(String key) {
        states.remove(key);
    }
}
