package com.codependent.oidc.resourceserver2.controller

import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor
import org.springframework.security.web.server.csrf.CsrfToken
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ModelAttribute
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono


/**
 * @author José A. Íñigo
 */
@ControllerAdvice
class SecurityControllerAdvice {
    @ModelAttribute
    fun csrfToken(exchange: ServerWebExchange): Mono<CsrfToken> {
        val csrfToken: Mono<CsrfToken> = exchange.getAttribute<Mono<CsrfToken>>(CsrfToken::class.java.getName())!!
        return csrfToken.doOnSuccess { token: CsrfToken? ->
            exchange.attributes[CsrfRequestDataValueProcessor.DEFAULT_CSRF_ATTR_NAME] = token
        }
    }
}
