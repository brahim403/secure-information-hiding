package tn.supcom.tessera.api;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

/**
 * JAX-RS application root. All resources are mounted under {@code /api/v1}.
 */
@ApplicationPath("/api/v1")
public class TesseraApplication extends Application {
}
