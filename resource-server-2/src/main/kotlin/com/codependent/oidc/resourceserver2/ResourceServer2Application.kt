package com.codependent.oidc.resourceserver2

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class ResourceServer2Application

fun main(args: Array<String>) {
	runApplication<ResourceServer2Application>(*args)
}
