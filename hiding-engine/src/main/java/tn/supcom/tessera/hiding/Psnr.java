package tn.supcom.tessera.hiding;

import java.awt.image.BufferedImage;

/** Peak signal-to-noise ratio (dB) over the RGB channels — the marking quality metric (PSNR ≥ 40 dB). */
public final class Psnr {

    private Psnr() {
    }

    public static double psnr(BufferedImage a, BufferedImage b) {
        int w = a.getWidth();
        int h = a.getHeight();
        long sum = 0;
        long count = 0;
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int pa = a.getRGB(x, y);
                int pb = b.getRGB(x, y);
                for (int shift = 0; shift <= 16; shift += 8) {
                    int d = ((pa >> shift) & 0xFF) - ((pb >> shift) & 0xFF);
                    sum += (long) d * d;
                    count++;
                }
            }
        }
        if (sum == 0) {
            return Double.POSITIVE_INFINITY;
        }
        double mse = (double) sum / count;
        return 10.0 * Math.log10((255.0 * 255.0) / mse);
    }
}
