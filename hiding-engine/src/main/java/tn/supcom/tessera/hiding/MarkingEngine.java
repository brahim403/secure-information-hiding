package tn.supcom.tessera.hiding;

import java.awt.image.BufferedImage;

/**
 * Orchestrates the ordered hiding pipeline (SEC-DC-04/06):
 * frequency-domain insertion (DCT 8x8 / QIM robust marks) FIRST, then the fragile
 * LSB seal LAST. Quality is controlled by PSNR; the caller is expected to reject a
 * result below {@link #MIN_PSNR_DB}.
 */
public final class MarkingEngine {

    /** Default parameters tuned for PSNR ≥ 40 dB with moderate-JPEG robustness. */
    public static final double DELTA = 26.0;
    public static final int COEFF_U = 2;
    public static final int COEFF_V = 1;
    public static final int REDUNDANCY = 28;
    public static final double MIN_PSNR_DB = 40.0;

    private MarkingEngine() {
    }

    /** Embeds the robust payload in luminance, then the fragile seal in the LSBs. */
    public static BufferedImage mark(BufferedImage source, boolean[] robustBits,
                                     byte[] sealPayload, long sealKey) {
        YCbCr ycc = YCbCr.fromRgb(source);
        RobustWatermark.embed(ycc.y, robustBits, DELTA, COEFF_U, COEFF_V, REDUNDANCY);
        BufferedImage marked = ycc.toRgb();
        FragileSeal.embed(marked, sealPayload, sealKey);
        return marked;
    }

    /** Recovers the robust payload (survives moderate attacks). */
    public static boolean[] extractRobust(BufferedImage image, int nbits) {
        YCbCr ycc = YCbCr.fromRgb(image);
        return RobustWatermark.extract(ycc.y, nbits, DELTA, COEFF_U, COEFF_V, REDUNDANCY);
    }

    public static int hammingDistance(boolean[] a, boolean[] b) {
        int d = 0;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                d++;
            }
        }
        return d;
    }
}
