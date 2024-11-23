package org.stepup.cinesquareapis.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import io.swagger.v3.core.jackson.ModelResolver;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.media.StringSchema;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springdoc.core.customizers.OperationCustomizer;

@Configuration
public class SwaggerConfig {
    private static final String SECURITY_SCHEME_NAME = "authorization";

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes(SECURITY_SCHEME_NAME, new SecurityScheme()
                                .name(SECURITY_SCHEME_NAME)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("Bearer")
                                .bearerFormat("JWT"))
                        .addParameters("Refresh-Token", new Parameter()
                                .in("cookie")
                                .schema(new StringSchema())
                                .name("Refresh-Token")
                                .description("액세스 토큰 재발급을 위해 리프레시 토큰 사용")))
                .addSecurityItem(new SecurityRequirement().addList(SECURITY_SCHEME_NAME))
                .info(apiInfo());
    }

    private Info apiInfo() {
        return new Info()
                .title("CINESQUARE API")
                .description("필요시 access_token을 우측 상단 Authorize에 입력하여 로그인 후 사용")
                .version("1.0.0");
    }

    @Bean
    public ModelResolver modelResolver(ObjectMapper objectMapper) {
        return new ModelResolver(objectMapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE));
    }

    @Bean
    public OperationCustomizer globalHeader() {
        return (operation, handlerMethod) -> {
            operation.addParametersItem(new Parameter()
                    .in("header")
                    .schema(new StringSchema().name("Refresh-Token"))
                    .name("Refresh-Token"));
//                    .description("리프레시 토큰 (Header > Cookies > Refresh-Token 으로 요청할 수 있음"));
            return operation;
        };
    }
}
