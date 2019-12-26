package com.codependent.oidc.resourceserver2.controller

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono


/**
 * @author José A. Íñigo
 */
@Controller
class HomeController(private val webClient: WebClient) {

    @GetMapping
    fun home(@RegisteredOAuth2AuthorizedClient authorizedClient: OAuth2AuthorizedClient,
             @AuthenticationPrincipal oauth2User: OAuth2User): Mono<String> {
        return ReactiveSecurityContextHolder.getContext()
                .doOnNext {
                    println(it.authentication)
                }.flatMap {
                    webClient.get().uri("http://localhost:8181/resource-server-1/rest/hello").retrieve()
                            .bodyToMono(Pair::class.java)
                            .onErrorResume { Mono.empty() }
                            .doOnNext { println(it) }
                            .doOnError { it.printStackTrace() }
                            .map { "home" }
                }
    }

}
