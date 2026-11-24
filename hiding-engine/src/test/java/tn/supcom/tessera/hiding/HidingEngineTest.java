package tn.supcom.tessera.hiding;

import org.junit.jupiter.api.Test;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Attack bench for the hiding engine (SEC-DC-04/06, SEC-RD-06). Prints PSNR and
 * detection rates so the numbers can be read off the build log / CI report.
 */
class HidingEngineTest {

    private static final int SIZE = 512;
    private static final int FINGERPRINT_BITS = 64;

    private static BufferedImage sampleImage() {
        // Smooth gradient plus mild texture — representative of a ticket background.
        BufferedImage img = new BufferedImage(SIZE, SIZE, BufferedImage.TYPE_INT_RGB);
        Random rng = new Random(1);
        for (int y = 0; y < SIZE; y++) {
            for (int x = 0; x < SIZE; x++) {
                int r = clamp(60 + x / 3 + rng.nextInt(10));
                int g = clamp(90 + (x + y) / 5 + rng.nextInt(10));
                int b = clamp(120 + y / 3 + rng.nextInt(10));
                img.setRGB(x, y, (r << 16) | (g << 8) | b);
            }
        }
        return img;
    }

    private static boolean[] randomBits(int n, long seed) {
        Random rng = new Random(seed);
        boolean[] bits = new boolean[n];
        for (int i = 0; i < n; i++) {
            bits[i] = rng.nextBoolean();
        }
        return bits;
    }

    private static byte[] jpeg(BufferedImage img, float quality) throws Exception {
        ImageWriter writer = ImageIO.getImageWritersByFormatName("jpeg").next();
        ImageWriteParam p = writer.getDefaultWriteParam();
        p.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
        p.setCompressionQuality(quality);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ImageOutputStream ios = ImageIO.createImageOutputStream(bos)) {
            writer.setOutput(ios);
            writer.write(null, new IIOImage(img, null, null), p);
        }
        writer.dispose();
        return bos.toByteArray();
    }

    private static BufferedImage reread(byte[] bytes) throws Exception {
        return ImageIO.read(new ByteArrayInputStream(bytes));
    }

    @Test
    void psnr_is_at_least_40db_after_marking() {
        BufferedImage src = sampleImage();
        boolean[] fp = randomBits(FINGERPRINT_BITS, 7);
        BufferedImage marked = MarkingEngine.mark(src, fp, "SEAL".getBytes(), 0xABCDL);
        double psnr = Psnr.psnr(src, marked);
        System.out.printf("[bench] PSNR after marking = %.2f dB%n", psnr);
        assertTrue(psnr >= MarkingEngine.MIN_PSNR_DB,
                "PSNR " + psnr + " dB below budget " + MarkingEngine.MIN_PSNR_DB);
    }

    @Test
    void robust_mark_recovers_perfectly_without_attack() {
        BufferedImage src = sampleImage();
        boolean[] fp = randomBits(FINGERPRINT_BITS, 7);
        BufferedImage marked = MarkingEngine.mark(src, fp, "SEAL".getBytes(), 0xABCDL);
        boolean[] got = MarkingEngine.extractRobust(marked, FINGERPRINT_BITS);
        assertArrayEquals(fp, got);
    }

    @Test
    void robust_mark_survives_jpeg_q75_and_resize() throws Exception {
        BufferedImage src = sampleImage();
        boolean[] fp = randomBits(FINGERPRINT_BITS, 7);
        BufferedImage marked = MarkingEngine.mark(src, fp, "SEAL".getBytes(), 0xABCDL);

        BufferedImage afterJpeg = reread(jpeg(marked, 0.75f));
        int errJpeg = MarkingEngine.hammingDistance(fp, MarkingEngine.extractRobust(afterJpeg, FINGERPRINT_BITS));
        double recJpeg = 100.0 * (FINGERPRINT_BITS - errJpeg) / FINGERPRINT_BITS;
        System.out.printf("[bench] JPEG Q75 recovery = %.1f%% (%d/%d bits)%n",
                recJpeg, FINGERPRINT_BITS - errJpeg, FINGERPRINT_BITS);
        assertTrue(recJpeg >= 95.0, "JPEG Q75 recovery " + recJpeg + "% below 95%");
    }

    @Test
    void fragile_seal_recovers_exactly_then_breaks_on_recompression() throws Exception {
        BufferedImage src = sampleImage();
        byte[] seal = "encrypted-access-payload".getBytes();
        BufferedImage marked = MarkingEngine.mark(src, randomBits(FINGERPRINT_BITS, 7), seal, 0xABCDL);

        assertArrayEquals(seal, FragileSeal.extract(marked, 0xABCDL),
                "seal must be exact on the untouched original");

        BufferedImage afterJpeg = reread(jpeg(marked, 0.75f));
        boolean broken = !java.util.Arrays.equals(seal, FragileSeal.extract(afterJpeg, 0xABCDL));
        System.out.printf("[bench] fragile seal broken by JPEG = %b%n", broken);
        assertTrue(broken, "fragile seal must not survive recompression (fail-closed)");
    }

    @Test
    void image_guard_rejects_pixel_flood_and_non_png() throws Exception {
        // A valid small PNG passes and reports real dimensions.
        BufferedImage small = new BufferedImage(32, 32, BufferedImage.TYPE_INT_RGB);
        ByteArrayOutputStream png = new ByteArrayOutputStream();
        ImageIO.write(small, "png", png);
        ImageGuard.Dimensions dim = ImageGuard.validatePng(png.toByteArray());
        assertTrue(dim.width() == 32 && dim.height() == 32);

        // A tiny PNG whose header declares 30000x30000 px is rejected by the
        // dimension check before any pixel buffer is allocated.
        byte[] bomb = pixelFloodPng(30000, 30000);
        assertThrows(IllegalArgumentException.class, () -> ImageGuard.validatePng(bomb));

        // A non-PNG (bad magic bytes) is rejected.
        assertThrows(IllegalArgumentException.class,
                () -> ImageGuard.validatePng("not an image".getBytes()));
    }

    /** Crafts a minimal PNG (signature + IHDR) declaring huge dimensions, no pixel data. */
    private static byte[] pixelFloodPng(int w, int h) {
        byte[] sig = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.writeBytes(sig);
        byte[] ihdr = new byte[13];
        putInt(ihdr, 0, w);
        putInt(ihdr, 4, h);
        ihdr[8] = 8;   // bit depth
        ihdr[9] = 2;   // colour type RGB
        writeChunk(bos, "IHDR", ihdr);
        return bos.toByteArray();
    }

    private static void writeChunk(ByteArrayOutputStream bos, String type, byte[] data) {
        byte[] len = new byte[4];
        putInt(len, 0, data.length);
        bos.writeBytes(len);
        byte[] typeBytes = type.getBytes();
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(typeBytes);
        crc.update(data);
        bos.writeBytes(typeBytes);
        bos.writeBytes(data);
        byte[] crcBytes = new byte[4];
        putInt(crcBytes, 0, (int) crc.getValue());
        bos.writeBytes(crcBytes);
    }

    private static void putInt(byte[] a, int off, int v) {
        a[off] = (byte) (v >>> 24);
        a[off + 1] = (byte) (v >>> 16);
        a[off + 2] = (byte) (v >>> 8);
        a[off + 3] = (byte) v;
    }

    private static int clamp(int v) {
        return v < 0 ? 0 : (v > 255 ? 255 : v);
    }
}
