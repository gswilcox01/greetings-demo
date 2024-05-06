package com.example.demo.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class Security5NoSoupConfig {

    @Bean
    @Order(5)
    public SecurityFilterChain noSoupFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/v5/**")
            .authorizeHttpRequests((authz) -> authz
                    .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                    .anyRequest().denyAll()
            );
        return http.build();
    }
}