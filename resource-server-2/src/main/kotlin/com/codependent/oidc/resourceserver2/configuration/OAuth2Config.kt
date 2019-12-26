package com.codependent.oidc.resourceserver2.configuration

import com.codependent.oidc.resourceserver2.client.ServerBearerExchangeFilterFunction
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.web.ServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.WebFilter
import java.net.URI


/**
 * @author José A. Íñigo
 */
@Configuration
@EnableWebFluxSecurity
class OAuth2Config {

    @Autowired
    lateinit var serverProperties: ServerProperties

    @Autowired
    lateinit var oAuth2AuthorizedClientRepository: ServerOAuth2AuthorizedClientRepository

    @Bean
    fun webClient(): WebClient {
        val servletBearerExchangeFilterFunction = ServerBearerExchangeFilterFunction("resource-server-2",
                oAuth2AuthorizedClientRepository)
        return WebClient.builder()
                .filter(servletBearerExchangeFilterFunction)
                .build()
    }

    @Bean
    fun clientRegistrationRepository(): ReactiveClientRegistrationRepository {
        return InMemoryReactiveClientRegistrationRepository(keycloakClientRegistration())
    }

    @Bean
    fun jwtDecoder(): ReactiveJwtDecoder {
        return ReactiveJwtDecoders.fromIssuerLocation("http://localhost:8080/auth/realms/insight")
    }

    private fun keycloakClientRegistration(): ClientRegistration {
        return ClientRegistration
                .withRegistrationId("resource-server-2")
                .clientId("resource-server-2")
                .clientSecret("e8775c0b-2a5c-4a4c-9aee-db0678c9d59d")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email", "address", "phone")
                .authorizationUri("http://localhost:8080/auth/realms/insight/protocol/openid-connect/auth")
                .tokenUri("http://localhost:8080/auth/realms/insight/protocol/openid-connect/token")
                .userInfoUri("http://localhost:8080/auth/realms/insight/protocol/openid-connect/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri("http://localhost:8080/auth/realms/insight/protocol/openid-connect/certs")
                .clientName("Keycloak")
                .providerConfigurationMetadata(mapOf("end_session_endpoint" to "http://localhost:8080/auth/realms/insight/protocol/openid-connect/logout"))
                .build()
    }

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http.authorizeExchange { exchanges ->
            exchanges
                    .anyExchange().authenticated()

        }.oauth2Login(withDefaults())
                .logout { logout ->
                    logout.logoutUrl("/resource-server-2/logout")
                    logout.logoutSuccessHandler(oidcLogoutSuccessHandler())
                }
                .oauth2ResourceServer { resourceServer ->
                    resourceServer.jwt()
                            .jwtDecoder(jwtDecoder())
                }
                .build()
    }

    @Bean
    fun contextPathWebFilter(): WebFilter {
        val contextPath = serverProperties.servlet.contextPath
        return WebFilter { exchange, chain ->
            val request = exchange.request
            if (request.uri.path.startsWith(contextPath)) {
                chain.filter(
                        exchange.mutate()
                                .request(request.mutate().contextPath(contextPath).build())
                                .build())
            } else {
                chain.filter(exchange)
            }
        }
    }

    private fun oidcLogoutSuccessHandler(): ServerLogoutSuccessHandler? {
        val oidcLogoutSuccessHandler = OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository())
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create("http://localhost:8282/resource-server-2"))
        return oidcLogoutSuccessHandler
    }
}
