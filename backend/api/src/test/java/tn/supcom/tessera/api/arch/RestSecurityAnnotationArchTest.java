package tn.supcom.tessera.api.arch;

import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;

/**
 * Fail-safe-defaults architecture test (SEC-AZ-01).
 *
 * <p>Every Jakarta REST resource method MUST declare an explicit access-control
 * annotation: {@code @RolesAllowed}, {@code @PermitAll} or {@code @DenyAll}. A
 * missing annotation fails the build, so no endpoint can ship with an implicit
 * or forgotten authorization policy.</p>
 *
 * <p>Resource methods are detected the canonical JAX-RS way: a request-handling
 * method is meta-annotated with {@code jakarta.ws.rs.HttpMethod} (true for
 * {@code @GET}, {@code @POST}, {@code @PUT}, {@code @DELETE}, {@code @PATCH},
 * {@code @HEAD}, {@code @OPTIONS} and any custom HTTP method).</p>
 */
@AnalyzeClasses(
        packages = "tn.supcom.tessera.api",
        importOptions = ImportOption.DoNotIncludeTests.class)
public class RestSecurityAnnotationArchTest {

    private static final String HTTP_METHOD = "jakarta.ws.rs.HttpMethod";

    /** Access-control annotations, exactly one of which is required. */
    private static final String[] ACCESS_CONTROL_ANNOTATIONS = {
            "jakarta.annotation.security.RolesAllowed",
            "jakarta.annotation.security.PermitAll",
            "jakarta.annotation.security.DenyAll"
    };

    private static final ArchCondition<JavaMethod> HAVE_AN_ACCESS_CONTROL_ANNOTATION =
            new ArchCondition<>("declare @RolesAllowed, @PermitAll or @DenyAll") {
                @Override
                public void check(JavaMethod method, ConditionEvents events) {
                    boolean secured = false;
                    for (String ac : ACCESS_CONTROL_ANNOTATIONS) {
                        if (method.isAnnotatedWith(ac)) {
                            secured = true;
                            break;
                        }
                    }
                    if (!secured) {
                        events.add(SimpleConditionEvent.violated(
                                method,
                                "REST method " + method.getFullName()
                                        + " has no access-control annotation (SEC-AZ-01)"));
                    }
                }
            };

    @ArchTest
    static final ArchRule rest_methods_must_declare_access_control =
            methods()
                    .that().areMetaAnnotatedWith(HTTP_METHOD)
                    .should(HAVE_AN_ACCESS_CONTROL_ANNOTATION)
                    .as("Every Jakarta REST method must declare an explicit access-control annotation (SEC-AZ-01)");
}
