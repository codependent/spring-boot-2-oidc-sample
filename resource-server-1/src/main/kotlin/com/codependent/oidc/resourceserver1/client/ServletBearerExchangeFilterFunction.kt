package com.codependent.oidc.resourceserver1.client

import org.springframework.http.HttpHeaders
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.core.AbstractOAuth2Token
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.ExchangeFilterFunction
import org.springframework.web.reactive.function.client.ExchangeFunction
import reactor.core.publisher.Mono
import reactor.util.context.Context

/**
 * @author José A. Íñigo
 */

const val SECURITY_REACTOR_CONTEXT_ATTRIBUTES_KEY = "org.springframework.security.SECURITY_CONTEXT_ATTRIBUTES"

class ServletBearerExchangeFilterFunction(private val clientRegistrationId: String,
                                          private val oAuth2AuthorizedClientRepository: OAuth2AuthorizedClientRepository?) : ExchangeFilterFunction {

    /**
     * {@inheritDoc}
     */
    override fun filter(request: ClientRequest, next: ExchangeFunction): Mono<ClientResponse> {
        return oauth2Token()
                .map { token: AbstractOAuth2Token -> bearer(request, token) }
                .defaultIfEmpty(request)
                .flatMap { request: ClientRequest -> next.exchange(request) }
    }

    private fun oauth2Token(): Mono<AbstractOAuth2Token> {
        return Mono.subscriberContext()
                .flatMap { ctx: Context -> currentAuthentication(ctx) }
                .map { authentication ->
                    val authorizedClient = oAuth2AuthorizedClientRepository?.loadAuthorizedClient<OAuth2AuthorizedClient>(clientRegistrationId, authentication, null)
                    if (authorizedClient != null) {
                        authorizedClient.accessToken
                    } else {
                        Unit
                    }
                }
                .filter { it != null }
                .cast(AbstractOAuth2Token::class.java)
    }

    private fun currentAuthentication(ctx: Context): Mono<Authentication> {
        return Mono.justOrEmpty(getAttribute(ctx, Authentication::class.java))
    }

    private fun <T> getAttribute(ctx: Context, clazz: Class<T>): T? { // NOTE: SecurityReactorContextConfiguration.SecurityReactorContextSubscriber adds this key
        if (!ctx.hasKey(SECURITY_REACTOR_CONTEXT_ATTRIBUTES_KEY)) {
            return null
        }
        val attributes: Map<Class<T>, T> = ctx[SECURITY_REACTOR_CONTEXT_ATTRIBUTES_KEY]
        return attributes[clazz]
    }

    private fun bearer(request: ClientRequest, token: AbstractOAuth2Token): ClientRequest {
        return ClientRequest.from(request)
                .headers { headers: HttpHeaders -> headers.setBearerAuth(token.tokenValue) }
                .build()
    }

}

