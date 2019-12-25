package com.codependent.oidc.resourceserver2.controller

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.reactive.function.client.WebClient

/**
 * @author José A. Íñigo
 */
@Controller
class SingleLogoutController() {

    @GetMapping("/single-logout")
    fun logout() {
        println("*")
    }

}
