package com.codependent.oidc.resourceserver2.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.web.reactive.function.client.WebClient


/**
 * @author José A. Íñigo
 */
@Configuration
@EnableWebFluxSecurity
class WebClientConfiguration {

    @Bean
    fun webClient(reactiveClientRegistrationRepository: ReactiveClientRegistrationRepository,
                  authorizedClients: ServerOAuth2AuthorizedClientRepository): WebClient {
        val oauth = ServerOAuth2AuthorizedClientExchangeFilterFunction(reactiveClientRegistrationRepository, authorizedClients)
        return WebClient.builder()
                .filter(oauth)
                .build()
    }

}
