package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableScheduling
public class Security1BasicAuthConfig {
    @Bean
    @Order(1)
    public SecurityFilterChain basicAuthFilterChain(HttpSecurity http) throws Exception {
        // see 5.8 config examples here: https://docs.spring.io/spring-security/reference/5.8/migration/servlet/config.html
        // see securityMatchers, if you want to limit this filterChain to a subset of paths
        http
                .securityMatcher("/v1/**")
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/v1/greetings/**").authenticated()
                        .anyRequest().denyAll()
                )
                .httpBasic(Customizer.withDefaults())
                .csrf().disable();
        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.builder()
                .username("gary")
                .password(passwordEncoder().encode("pass"))
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("pass"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(); // or use SHA-256 instead of BCrypt
        // return new org.springframework.security.crypto.password.NoOpPasswordEncoder(); // disable password encoding for testing purposes
        // return new org.springframework.security.crypto.password.Pbkdf2PasswordEncoder(); // use PBKDF2 instead of BCrypt
        // return new org.springframework.security.crypto.password.ScryptPasswordEncoder(); // use SCrypt instead of BCrypt
        // return new org.springframework.security.crypto.password.StandardPasswordEncoder(); // use SHA-256 instead of BCrypt
        // return new org.springframework.security.crypto.password.UUIDPasswordEncoder(); // use UUID instead of BCrypt
        // return new org.springframework.security.crypto.password.Windows95PasswordEncoder(); // use Windows95 password format instead of BCrypt
        // return new org.springframework.security.crypto.password.YamlPasswordEncoder(); // use YAML password format instead of BCrypt
        // return new org.springframework.security.crypto.password.scrypt.SCryptPasswordEncoder(); // use SC
    }
}