package com.codependent.oidc.resourceserver2.client

import org.springframework.http.HttpHeaders
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AbstractOAuth2Token
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.ExchangeFilterFunction
import org.springframework.web.reactive.function.client.ExchangeFunction
import reactor.core.publisher.Mono

/**
 * @author José A. Íñigo
 */
class ServerBearerExchangeFilterFunction(private val clientRegistrationId: String,
                                         private val oAuth2AuthorizedClientRepository: ServerOAuth2AuthorizedClientRepository?) : ExchangeFilterFunction {

    override fun filter(request: ClientRequest, next: ExchangeFunction): Mono<ClientResponse> {
        return oauth2Token()
                .map { token -> bearer(request, token as AbstractOAuth2Token) }
                .defaultIfEmpty(request)
                .flatMap { request: ClientRequest -> next.exchange(request) }
    }

    private fun oauth2Token(): Mono<AbstractOAuth2Token> {
        return currentAuthentication()
                .flatMap { authentication ->
                    oAuth2AuthorizedClientRepository?.loadAuthorizedClient<OAuth2AuthorizedClient>(clientRegistrationId, authentication, null)?.map { it.accessToken }
                }
                .filter { it != null }
                .cast(AbstractOAuth2Token::class.java)
    }

    private fun currentAuthentication(): Mono<Authentication> {
        return ReactiveSecurityContextHolder.getContext()
                .map { obj: SecurityContext -> obj.authentication }
    }

    private fun bearer(request: ClientRequest, token: AbstractOAuth2Token): ClientRequest {
        return ClientRequest.from(request)
                .headers { headers: HttpHeaders -> headers.setBearerAuth(token.tokenValue) }
                .build()
    }
}

