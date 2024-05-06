package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class Security3Oauth2Config {

    @Bean
    @Order(3)
    public SecurityFilterChain oauth2FilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/v3/**")
            .authorizeHttpRequests((authz) -> authz
                .requestMatchers(HttpMethod.POST, "/v3/greetings/**").hasAuthority("SCOPE_greetings.write")
                .requestMatchers(HttpMethod.PUT, "/v3/greetings/**").hasAuthority("SCOPE_greetings.write")
                .requestMatchers(HttpMethod.DELETE, "/v3/greetings/**").hasAuthority("SCOPE_greetings.write")
                .requestMatchers(HttpMethod.GET, "/v3/greetings/**").hasAnyAuthority("SCOPE_greetings.write", "SCOPE_greetings.read")
                .anyRequest().denyAll()
            )
            .csrf().disable()
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwkSetUri("http://localhost:8080/oauth2/jwks")
                )
            );
        return http.build();
    }
}