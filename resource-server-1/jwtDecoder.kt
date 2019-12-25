@Bean
    fun jwtDecoder(): JwtDecoder {
        return JwtDecoders.fromIssuerLocation("http://localhost:8080/auth/realms/insight")
    }
