package com.codependent.oidc.resourceserver1.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtDecoders
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import java.net.URI


/**
 * @author José A. Íñigo
 */
@Configuration
class SecurityConfiguration : WebSecurityConfigurerAdapter() {

    private val authorities = mapOf("codependent" to setOf("viewer-resource-server-1", "editor-resource-server-1"))

    @Bean
    fun clientRegistrationRepository() = InMemoryClientRegistrationRepository(keycloakClientRegistration())

    @Bean
    fun jwtDecoder(): JwtDecoder = JwtDecoders.fromIssuerLocation("http://localhost:8080/auth/realms/insight")

    @Bean
    fun userAuthoritiesMapper(): GrantedAuthoritiesMapper {
        return GrantedAuthoritiesMapper { authorities ->
            val mappedAuthorities = mutableSetOf<GrantedAuthority>()

            authorities.forEach { authority ->
                mappedAuthorities.add(SimpleGrantedAuthority(authority.authority))
                if (authority is OidcUserAuthority) {
                    val oidcUserAuthority = authority

                    val idToken = oidcUserAuthority.idToken
                    val userInfo = oidcUserAuthority.userInfo

                    // Map the claims found in idToken and/or userInfo
                    // to one or more GrantedAuthority's and add it to mappedAuthorities
                    this.authorities[userInfo.preferredUsername]?.forEach {
                        mappedAuthorities.add(SimpleGrantedAuthority("ROLE_$it"))
                    }

                } else if (authority is OAuth2UserAuthority) {
                    val oauth2UserAuthority = authority

                    val userAttributes = oauth2UserAuthority.attributes

                    // Map the attributes found in userAttributes
                    // to one or more GrantedAuthority's and add it to mappedAuthorities

                }
            }
            mappedAuthorities
        }
    }

    override fun configure(http: HttpSecurity) {
        http.authorizeRequests { authorizeRequests ->
            authorizeRequests
                    .anyRequest().authenticated()
        }.oauth2Login(withDefaults())
                .logout { logout ->
                    logout.logoutSuccessHandler(oidcLogoutSuccessHandler())
                }
                .oauth2ResourceServer { oauth2ResourceServer ->
                    oauth2ResourceServer.jwt { jwt ->
                        jwt.decoder(jwtDecoder())
                        jwt.jwtAuthenticationConverter(grantedAuthoritiesExtractor())
                    }
                }
                .oauth2Client(withDefaults())
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

    private fun oidcLogoutSuccessHandler(): LogoutSuccessHandler {
        val oidcLogoutSuccessHandler = OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository())
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create("http://localhost:8181/resource-server-1"))
        return oidcLogoutSuccessHandler
    }

    private fun grantedAuthoritiesExtractor(): Converter<Jwt, AbstractAuthenticationToken> {
        return GrantedAuthoritiesExtractor()
    }

    inner class GrantedAuthoritiesExtractor : JwtAuthenticationConverter() {
        override fun extractAuthorities(jwt: Jwt): MutableCollection<GrantedAuthority> {
            val extractedAuthorities = super.extractAuthorities(jwt)
            authorities[jwt.getClaimAsString("preferred_username")]?.forEach {
                extractedAuthorities.add(SimpleGrantedAuthority("ROLE_$it"))
            }
            return extractedAuthorities
        }
    }

}
