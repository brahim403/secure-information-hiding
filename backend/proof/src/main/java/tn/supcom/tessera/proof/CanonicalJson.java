package tn.supcom.tessera.proof;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Deterministic canonical JSON serialization (a subset of JCS, RFC 8785)
 * sufficient for ticket claims: object keys are sorted, there is no insignificant
 * whitespace, and the supported value types are {@code String}, {@code Boolean},
 * integral numbers ({@code Integer}/{@code Long}), nested maps and lists.
 *
 * <p>Two logically equal claim sets therefore serialize to the exact same bytes,
 * which is what the Ed25519 signature is computed over (SEC-DC-01).</p>
 */
public final class CanonicalJson {

    private CanonicalJson() {
    }

    public static String canonicalize(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        switch (v) {
            case null -> sb.append("null");
            case String s -> writeString(sb, s);
            case Boolean b -> sb.append(b ? "true" : "false");
            case Integer i -> sb.append(i.toString());
            case Long l -> sb.append(l.toString());
            case Map<?, ?> m -> writeObject(sb, m);
            case List<?> list -> writeArray(sb, list);
            default -> throw new IllegalArgumentException(
                    "Unsupported canonical JSON type: " + v.getClass().getName());
        }
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> map) {
        // RFC 8785 sorts members by their key's UTF-16 code units; Java's natural
        // String ordering matches this for the (ASCII) keys used in claims.
        TreeMap<String, Object> sorted = new TreeMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            sorted.put(String.valueOf(e.getKey()), e.getValue());
        }
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> e : sorted.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            writeString(sb, e.getKey());
            sb.append(':');
            write(sb, e.getValue());
        }
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, List<?> list) {
        sb.append('[');
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            write(sb, item);
        }
        sb.append(']');
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
