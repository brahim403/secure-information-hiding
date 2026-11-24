package tn.supcom.tessera.hiding;

import java.awt.image.BufferedImage;
import java.util.Random;

/**
 * Fragile steganographic seal (SEC-DC-04). The (already encrypted) payload is
 * written into the least-significant bits of the blue channel at pseudo-random
 * positions derived from a key. It is applied LAST, after the robust marks, and
 * is intentionally fragile: any recompression or pixel edit destroys it, which
 * is exactly how tampering is detected (fail-closed at extraction).
 *
 * <p>Layout: 16-bit big-endian length prefix, then the payload bytes.</p>
 */
public final class FragileSeal {

    private FragileSeal() {
    }

    public static void embed(BufferedImage img, byte[] payload, long key) {
        int totalBits = 16 + payload.length * 8;
        int[] pos = positions(img, totalBits, key);
        int len = payload.length;
        for (int i = 0; i < totalBits; i++) {
            int bit = (i < 16)
                    ? (len >> (15 - i)) & 1
                    : (payload[(i - 16) / 8] >> (7 - ((i - 16) % 8))) & 1;
            setBlueLsb(img, pos[i], bit);
        }
    }

    public static byte[] extract(BufferedImage img, long key) {
        int[] head = positions(img, 16, key);
        int len = 0;
        for (int i = 0; i < 16; i++) {
            len = (len << 1) | blueLsb(img, head[i]);
        }
        if (len < 0 || len > (img.getWidth() * img.getHeight()) / 8) {
            return new byte[0];
        }
        int totalBits = 16 + len * 8;
        int[] pos = positions(img, totalBits, key);
        byte[] out = new byte[len];
        for (int i = 16; i < totalBits; i++) {
            int bit = blueLsb(img, pos[i]);
            out[(i - 16) / 8] |= (byte) (bit << (7 - ((i - 16) % 8)));
        }
        return out;
    }

    /** Deterministic distinct pixel indices for a given key (same for embed/extract). */
    private static int[] positions(BufferedImage img, int count, long key) {
        int n = img.getWidth() * img.getHeight();
        // Partial Fisher-Yates over a virtual identity permutation.
        Integer[] idx = new Integer[n];
        for (int i = 0; i < n; i++) {
            idx[i] = i;
        }
        Random rng = new Random(key);
        int[] out = new int[count];
        for (int i = 0; i < count; i++) {
            int j = i + rng.nextInt(n - i);
            Integer tmp = idx[i];
            idx[i] = idx[j];
            idx[j] = tmp;
            out[i] = idx[i];
        }
        return out;
    }

    private static void setBlueLsb(BufferedImage img, int pixelIndex, int bit) {
        int x = pixelIndex % img.getWidth();
        int y = pixelIndex / img.getWidth();
        int rgb = img.getRGB(x, y);
        rgb = (rgb & ~0x1) | bit;
        img.setRGB(x, y, rgb);
    }

    private static int blueLsb(BufferedImage img, int pixelIndex) {
        int x = pixelIndex % img.getWidth();
        int y = pixelIndex / img.getWidth();
        return img.getRGB(x, y) & 0x1;
    }
}
