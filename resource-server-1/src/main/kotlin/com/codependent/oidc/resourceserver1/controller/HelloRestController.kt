package com.codependent.oidc.resourceserver1.controller

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.AbstractOAuth2Token
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

/**
 * @author José A. Íñigo
 */
@RestController
class HelloRestController {

    @GetMapping("/rest/hello")
    fun hello(principal: Principal): Pair<String, String> {
        println(principal)
        val authentication = SecurityContextHolder.getContext().authentication
        println(authentication)
        println((authentication.credentials is AbstractOAuth2Token))
        return Pair("message", "hello from resource server 1")
    }
}
