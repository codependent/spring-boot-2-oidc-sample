package com.codependent.oidc.resourceserver2.configuration

import com.codependent.oidc.resourceserver2.client.ServerBearerExchangeFilterFunction
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.web.ServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.WebFilter
import reactor.core.publisher.Mono
import java.net.URI


/**
 * @author José A. Íñigo
 */
@Configuration
@EnableWebFluxSecurity
class OAuth2Config {

    private val authorities = mapOf("codependent" to setOf("viewer-resource-server-2", "editor-resource-server-2"))

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

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http.authorizeExchange { exchanges ->
            exchanges
                    .anyExchange().authenticated()

        }.oauth2Login {
        }
                .logout { logout ->
                    logout.logoutUrl("/resource-server-2/logout")
                    logout.logoutSuccessHandler(oidcLogoutSuccessHandler())
                }
                .oauth2ResourceServer { resourceServer ->
                    resourceServer.jwt()
                            .jwtDecoder(jwtDecoder())
                            .jwtAuthenticationConverter(grantedAuthoritiesExtractor())
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

    @Bean
    fun oidcUserService(): ReactiveOAuth2UserService<OidcUserRequest, OidcUser>  {
        val delegate = OidcReactiveOAuth2UserService()

        return ReactiveOAuth2UserService { userRequest ->
            val oidcUser = delegate.loadUser(userRequest)
                    .map {oidcUser ->
                        val accessToken = userRequest.accessToken
                        val mappedAuthorities = mutableSetOf<GrantedAuthority>()

                        // 1) Fetch the authority information from the protected resource using accessToken
                        // 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities

                        oidcUser.authorities.forEach {
                            mappedAuthorities.add(SimpleGrantedAuthority(it.authority))
                        }

                        this.authorities[oidcUser.preferredUsername]?.forEach {
                            mappedAuthorities.add(SimpleGrantedAuthority("ROLE_$it"))
                        }

                        // 3) Create a copy of oidcUser but use the mappedAuthorities instead
                        DefaultOidcUser(mappedAuthorities, oidcUser.idToken, oidcUser.userInfo) as OidcUser
                    }
            oidcUser
        }
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

    private fun oidcLogoutSuccessHandler(): ServerLogoutSuccessHandler? {
        val oidcLogoutSuccessHandler = OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository())
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create("http://localhost:8282/resource-server-2"))
        return oidcLogoutSuccessHandler
    }

    private fun grantedAuthoritiesExtractor(): Converter<Jwt, Mono<AbstractAuthenticationToken>> {
        val extractor = GrantedAuthoritiesExtractor()
        return ReactiveJwtAuthenticationConverterAdapter(extractor)
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
