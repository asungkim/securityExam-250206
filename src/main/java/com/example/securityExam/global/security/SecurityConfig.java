package com.example.securityExam.global.security;

import com.example.securityExam.global.dto.RsData;
import com.example.securityExam.standard.Ut;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationFilter customAuthenticationFilter;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/h2-console/**")
                        .permitAll()
                        .requestMatchers(HttpMethod.GET,
                                "/api/*/posts/{id:\\d+}",
                                "/api/*/posts",
                                "/api/*/posts/{postId:\\d+}/comments")
                        .permitAll()
                        .requestMatchers("/api/*/members/login", "/api/*/members/join")
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .headers((headers) -> headers
                        .addHeaderWriter(new XFrameOptionsHeaderWriter(
                                XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)))
                .csrf(csrf -> csrf.disable())
                .addFilterBefore(customAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(
                        exceptionHandling -> exceptionHandling
                                .authenticationEntryPoint(
                                        ((request, response, authException) -> {
                                            response.setStatus(401);
                                            response.setContentType("application/json;charset=UTF-8");
                                            response.getWriter().write(
                                                    Ut.json.toString(
                                                            new RsData<Void>("401-1", "잘못된 인증키입니다.")
                                                    )
                                            );
                                        })
                                )
                                .accessDeniedHandler(
                                        ((request, response, authException) -> {
                                            response.setStatus(403);
                                            response.setContentType("application/json;charset=UTF-8");
                                            response.getWriter().write(
                                                    Ut.json.toString(
                                                            new RsData<Void>("403-1", "접근 권한이 없습니다.")
                                                    )
                                            );
                                        })
                                )
                );
        return http.build();
    }
}
