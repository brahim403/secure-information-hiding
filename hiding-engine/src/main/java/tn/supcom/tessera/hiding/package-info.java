/**
 * Standalone image-marking engine (no Jakarta EE dependency).
 *
 * <p>Implements the ordered hiding pipeline: frequency-domain insertion
 * (DCT 8x8 / QIM) for the robust watermark and fingerprint, then the fragile LSB
 * seal, with PSNR &gt;= 40 dB quality control and fail-closed extraction.</p>
 */
package tn.supcom.tessera.hiding;
