package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class Security2NoAuthConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain noAuthFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/v2/**")
            .authorizeHttpRequests((authz) -> authz
                .anyRequest().permitAll()
            )
            .csrf().disable();
        return http.build();
    }
}