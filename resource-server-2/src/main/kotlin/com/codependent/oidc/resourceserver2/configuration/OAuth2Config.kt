package com.codependent.oidc.resourceserver2.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtDecoders
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.web.reactive.function.client.WebClient
import java.net.URI


/**
 * @author José A. Íñigo
 */
@Configuration
class OAuth2Config : WebSecurityConfigurerAdapter() {

    @Bean
    fun webClient(): WebClient {
        return WebClient.builder()
                .filter(ServletBearerExchangeFilterFunction())
                .build()
    }

    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository {
        return InMemoryClientRegistrationRepository(keycloakClientRegistration())
    }

    @Bean
    fun jwtDecoder(): JwtDecoder {
        return JwtDecoders.fromIssuerLocation("http://localhost:8080/auth/realms/insight")
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

    override fun configure(http: HttpSecurity) {
        http.authorizeRequests { authorizeRequests ->
            authorizeRequests
                    .anyRequest().authenticated()
        }.oauth2Login(Customizer.withDefaults())
                .logout { logout ->
                    logout.logoutSuccessHandler(oidcLogoutSuccessHandler())
                }
                .oauth2ResourceServer()
                .jwt()
                .decoder(jwtDecoder())
    }

    private fun oidcLogoutSuccessHandler(): LogoutSuccessHandler? {
        val oidcLogoutSuccessHandler = OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository())
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create("http://localhost:8282/resource-server-2"))
        return oidcLogoutSuccessHandler
    }
}
