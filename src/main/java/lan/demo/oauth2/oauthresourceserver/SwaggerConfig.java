package lan.demo.oauth2.oauthresourceserver;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.*;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(title = "oAuth demo", description = "resource server"),
        security = @SecurityRequirement(name = "security_auth")
)
@SecuritySchemes(
    @SecurityScheme(
            name = "security_auth",
            type = SecuritySchemeType.OAUTH2,
            scheme = "bearer", bearerFormat = "JWT",
            in = SecuritySchemeIn.HEADER,
            flows = @OAuthFlows(implicit = @OAuthFlow(authorizationUrl = "${springdoc.oAuthFlow.authorizationUrl}"))
    )
)
public class SwaggerConfig {
}
