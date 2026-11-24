package tn.supcom.tessera.hiding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

/**
 * Decoder-bomb defence (SEC-RD-06): verify the PNG magic bytes and read the
 * declared dimensions from the header <em>before</em> any pixel allocation, and
 * reject oversized inputs. This stops "pixel flood" images (a few KB declaring
 * tens of thousands of pixels per side) from exhausting the heap.
 */
public final class ImageGuard {

    public static final long MAX_BYTES = 5L * 1024 * 1024;   // 5 MB
    public static final long MAX_PIXELS = 16L * 1024 * 1024;  // 16 Mpx

    private static final byte[] PNG_SIGNATURE = {
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };

    private ImageGuard() {
    }

    public record Dimensions(int width, int height) {
    }

    /** @throws IllegalArgumentException if the bytes are not a safe, in-bounds PNG. */
    public static Dimensions validatePng(byte[] bytes) {
        if (bytes.length > MAX_BYTES) {
            throw new IllegalArgumentException("image exceeds max size (" + MAX_BYTES + " bytes)");
        }
        if (!hasPngSignature(bytes)) {
            throw new IllegalArgumentException("not a PNG (bad magic bytes)");
        }
        try (ImageInputStream iis = ImageIO.createImageInputStream(new ByteArrayInputStream(bytes))) {
            Iterator<ImageReader> readers = ImageIO.getImageReaders(iis);
            if (!readers.hasNext()) {
                throw new IllegalArgumentException("no PNG reader for input");
            }
            ImageReader reader = readers.next();
            try {
                reader.setInput(iis, true, true); // ignore metadata; only the header is read here
                int w = reader.getWidth(0);        // header only — no pixel buffer allocated
                int h = reader.getHeight(0);
                if ((long) w * h > MAX_PIXELS) {
                    throw new IllegalArgumentException("image exceeds max pixels (" + w + "x" + h + ")");
                }
                return new Dimensions(w, h);
            } finally {
                reader.dispose();
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("unreadable image header", e);
        }
    }

    private static boolean hasPngSignature(byte[] bytes) {
        if (bytes.length < PNG_SIGNATURE.length) {
            return false;
        }
        for (int i = 0; i < PNG_SIGNATURE.length; i++) {
            if (bytes[i] != PNG_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }
}
