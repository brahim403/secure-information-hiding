package tn.supcom.tessera.hiding;

/**
 * Robust watermark / fingerprint embedded by Quantization Index Modulation (QIM)
 * on one mid-frequency DCT coefficient of each 8x8 luminance block (SEC-DC-06).
 *
 * <p>Each payload bit is repeated across {@code redundancy} blocks and recovered
 * by majority vote, which is what lets it survive moderate JPEG recompression and
 * resizing. Dither QIM is used: bit 0 lands on the lattice {@code kΔ}, bit 1 on
 * {@code kΔ + Δ/2}.</p>
 */
public final class RobustWatermark {

    private RobustWatermark() {
    }

    public static void embed(double[][] luma, boolean[] bits, double delta,
                             int cu, int cv, int redundancy) {
        int blocksX = luma[0].length / Dct8x8.N;
        int needed = bits.length * redundancy;
        for (int b = 0; b < needed; b++) {
            int bx = b % blocksX;
            int by = b / blocksX;
            double[][] block = readBlock(luma, bx, by);
            double[][] f = Dct8x8.forward(block);
            f[cu][cv] = qimEmbed(f[cu][cv], delta, bits[b / redundancy] ? 1 : 0);
            writeBlock(luma, Dct8x8.inverse(f), bx, by);
        }
    }

    public static boolean[] extract(double[][] luma, int nbits, double delta,
                                    int cu, int cv, int redundancy) {
        int blocksX = luma[0].length / Dct8x8.N;
        int[] votes = new int[nbits];
        int needed = nbits * redundancy;
        for (int b = 0; b < needed; b++) {
            int bx = b % blocksX;
            int by = b / blocksX;
            double[][] f = Dct8x8.forward(readBlock(luma, bx, by));
            if (qimDecode(f[cu][cv], delta) == 1) {
                votes[b / redundancy]++;
            }
        }
        boolean[] out = new boolean[nbits];
        for (int i = 0; i < nbits; i++) {
            out[i] = votes[i] * 2 > redundancy;
        }
        return out;
    }

    private static double qimEmbed(double c, double delta, int bit) {
        double d = bit == 0 ? 0.0 : delta / 2.0;
        return Math.round((c - d) / delta) * delta + d;
    }

    private static int qimDecode(double c, double delta) {
        double p0 = Math.round(c / delta) * delta;
        double p1 = Math.round((c - delta / 2.0) / delta) * delta + delta / 2.0;
        return Math.abs(c - p0) <= Math.abs(c - p1) ? 0 : 1;
    }

    private static double[][] readBlock(double[][] luma, int bx, int by) {
        double[][] block = new double[Dct8x8.N][Dct8x8.N];
        for (int y = 0; y < Dct8x8.N; y++) {
            System.arraycopy(luma[by * Dct8x8.N + y], bx * Dct8x8.N, block[y], 0, Dct8x8.N);
        }
        return block;
    }

    private static void writeBlock(double[][] luma, double[][] block, int bx, int by) {
        for (int y = 0; y < Dct8x8.N; y++) {
            System.arraycopy(block[y], 0, luma[by * Dct8x8.N + y], bx * Dct8x8.N, Dct8x8.N);
        }
    }
}
