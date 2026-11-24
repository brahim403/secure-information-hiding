package tn.supcom.tessera.hiding;

/**
 * Orthonormal 8x8 2D DCT-II and its inverse. Because the transform is
 * orthonormal (B·Bᵀ = I), the inverse is the transpose: forward is B·f·Bᵀ and
 * inverse is Bᵀ·F·B. Parseval then holds, so the spatial distortion of a
 * coefficient change equals the coefficient change itself (keeps the watermark
 * within the PSNR budget).
 */
public final class Dct8x8 {

    public static final int N = 8;
    private static final double[][] B = basis();

    private Dct8x8() {
    }

    private static double[][] basis() {
        double[][] b = new double[N][N];
        for (int u = 0; u < N; u++) {
            double cu = (u == 0) ? Math.sqrt(1.0 / N) : Math.sqrt(2.0 / N);
            for (int x = 0; x < N; x++) {
                b[u][x] = cu * Math.cos(((2 * x + 1) * u * Math.PI) / (2.0 * N));
            }
        }
        return b;
    }

    /** Forward DCT: F = B · f · Bᵀ. */
    public static double[][] forward(double[][] f) {
        return rightByBt(leftByB(f));
    }

    /** Inverse DCT: f = Bᵀ · F · B. */
    public static double[][] inverse(double[][] big) {
        return rightByB(leftByBt(big));
    }

    /** (B · M)[i][j] = Σ_k B[i][k] · M[k][j]. */
    private static double[][] leftByB(double[][] m) {
        double[][] r = new double[N][N];
        for (int i = 0; i < N; i++) {
            for (int j = 0; j < N; j++) {
                double s = 0;
                for (int k = 0; k < N; k++) {
                    s += B[i][k] * m[k][j];
                }
                r[i][j] = s;
            }
        }
        return r;
    }

    /** (M · Bᵀ)[i][j] = Σ_k M[i][k] · B[j][k]. */
    private static double[][] rightByBt(double[][] m) {
        double[][] r = new double[N][N];
        for (int i = 0; i < N; i++) {
            for (int j = 0; j < N; j++) {
                double s = 0;
                for (int k = 0; k < N; k++) {
                    s += m[i][k] * B[j][k];
                }
                r[i][j] = s;
            }
        }
        return r;
    }

    /** (Bᵀ · M)[i][j] = Σ_k B[k][i] · M[k][j]. */
    private static double[][] leftByBt(double[][] m) {
        double[][] r = new double[N][N];
        for (int i = 0; i < N; i++) {
            for (int j = 0; j < N; j++) {
                double s = 0;
                for (int k = 0; k < N; k++) {
                    s += B[k][i] * m[k][j];
                }
                r[i][j] = s;
            }
        }
        return r;
    }

    /** (M · B)[i][j] = Σ_k M[i][k] · B[k][j]. */
    private static double[][] rightByB(double[][] m) {
        double[][] r = new double[N][N];
        for (int i = 0; i < N; i++) {
            for (int j = 0; j < N; j++) {
                double s = 0;
                for (int k = 0; k < N; k++) {
                    s += m[i][k] * B[k][j];
                }
                r[i][j] = s;
            }
        }
        return r;
    }
}
