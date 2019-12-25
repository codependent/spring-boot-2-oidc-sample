package com.codependent.oidc.resourceserver2.controller

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
        return Pair("message", "hello from resource server 2")
    }
}
