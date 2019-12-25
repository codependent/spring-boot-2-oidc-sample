package com.codependent.oidc.resourceserver2.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * @author José A. Íñigo
 */
@RestController
class HelloRestController {

    @GetMapping("/rest/hello")
    fun hello(): Pair<String, String> {
        return Pair("message", "hello from resource server 2")
    }
}
