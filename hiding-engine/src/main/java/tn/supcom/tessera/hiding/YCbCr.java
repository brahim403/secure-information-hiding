package tn.supcom.tessera.hiding;

import java.awt.image.BufferedImage;

/**
 * Full-range JFIF YCbCr conversion. The robust watermark is embedded in the
 * luminance (Y) plane — the component JPEG preserves best — while Cb/Cr are kept
 * unchanged, so colour is preserved and the mark survives moderate compression.
 */
public final class YCbCr {

    public final double[][] y;
    public final double[][] cb;
    public final double[][] cr;
    public final int width;
    public final int height;

    private YCbCr(double[][] y, double[][] cb, double[][] cr) {
        this.y = y;
        this.cb = cb;
        this.cr = cr;
        this.height = y.length;
        this.width = y[0].length;
    }

    public static YCbCr fromRgb(BufferedImage img) {
        int h = img.getHeight();
        int w = img.getWidth();
        double[][] y = new double[h][w];
        double[][] cb = new double[h][w];
        double[][] cr = new double[h][w];
        for (int j = 0; j < h; j++) {
            for (int i = 0; i < w; i++) {
                int rgb = img.getRGB(i, j);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                y[j][i] = 0.299 * r + 0.587 * g + 0.114 * b;
                cb[j][i] = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b;
                cr[j][i] = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b;
            }
        }
        return new YCbCr(y, cb, cr);
    }

    public BufferedImage toRgb() {
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int j = 0; j < height; j++) {
            for (int i = 0; i < width; i++) {
                double yy = y[j][i];
                double pcb = cb[j][i] - 128;
                double pcr = cr[j][i] - 128;
                int r = clamp(yy + 1.402 * pcr);
                int g = clamp(yy - 0.344136 * pcb - 0.714136 * pcr);
                int b = clamp(yy + 1.772 * pcb);
                img.setRGB(i, j, (r << 16) | (g << 8) | b);
            }
        }
        return img;
    }

    private static int clamp(double v) {
        long r = Math.round(v);
        if (r < 0) {
            return 0;
        }
        return (r > 255) ? 255 : (int) r;
    }
}
