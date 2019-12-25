package com.codependent.oidc.resourceserver1.controller

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.reactive.function.client.WebClient
import javax.servlet.http.HttpSession

/**
 * @author José A. Íñigo
 */
@Controller
class HomeController(private val webClient: WebClient) {

    @GetMapping
    fun home(httpSession: HttpSession,
             @RegisteredOAuth2AuthorizedClient authorizedClient: OAuth2AuthorizedClient,
             @AuthenticationPrincipal oauth2User: OAuth2User): String {
        val authentication = SecurityContextHolder.getContext().authentication
        println(authentication)

        val pair = webClient.get().uri("http://localhost:8181/rest/hello").retrieve()
                .bodyToMono(Pair::class.java)
                .block()

        println(pair)

        return "home"
    }

}
