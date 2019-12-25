package com.codependent.oidc.resourceserver1.configuration

import com.codependent.oidc.resourceserver1.client.ServletBearerExchangeFilterFunction
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtDecoders
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.web.reactive.function.client.WebClient
import java.net.URI


/**
 * @author José A. Íñigo
 */
@Configuration
class OAuth2Config : WebSecurityConfigurerAdapter() {

    @Autowired
    lateinit var oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository

    @Bean
    fun webClient(): WebClient {
        val servletBearerExchangeFilterFunction = ServletBearerExchangeFilterFunction("resource-server-1",
                oAuth2AuthorizedClientRepository)
        return WebClient.builder()
                .filter(servletBearerExchangeFilterFunction)
                .build()
    }

    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository {
        return InMemoryClientRegistrationRepository(keycloakClientRegistration())
    }

    private fun keycloakClientRegistration(): ClientRegistration {
        return ClientRegistration
                .withRegistrationId("resource-server-1")
                .clientId("resource-server-1")
                .clientSecret("c00670cc-8546-4d5f-946e-2a0e998b9d7f")
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
    fun jwtDecoder(): JwtDecoder {
        return JwtDecoders.fromIssuerLocation("http://localhost:8080/auth/realms/insight")
    }

    override fun configure(http: HttpSecurity) {
        http.authorizeRequests { authorizeRequests ->
            authorizeRequests
                    .anyRequest().authenticated()
        }.oauth2Login(withDefaults())
                .logout { logout ->
                    logout.logoutSuccessHandler(oidcLogoutSuccessHandler())
                }
                .oauth2ResourceServer()
                .jwt()
                .decoder(jwtDecoder())
    }

    private fun oidcLogoutSuccessHandler(): LogoutSuccessHandler? {
        val oidcLogoutSuccessHandler = OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository())
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create("http://localhost:8181/resource-server-1"))
        return oidcLogoutSuccessHandler
    }
}
