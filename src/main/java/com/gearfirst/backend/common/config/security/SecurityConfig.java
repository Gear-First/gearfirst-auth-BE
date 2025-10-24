package com.gearfirst.backend.common.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfigurationSource;



import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * AuthenticationManager Bean 등록
     * 두 FilterChain이 동일한 AuthenticationManager를 공유히도록 함
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        //여기서 UserDetailService와 PasswordEncoder를 명시적으로 설정할 수도 있음
        return authBuilder.build();
    }


    /**
     * Authorization Server용 SecurityFilterChain
     * (OAuth2.0 endpoints: /oauth2/authorize(클라이언트가 인가 코드 요청), /oauth2/token(accessToken 교환), /oauth2/jwks(공개키제공) 등)
     */
    @Bean
    @Order(1) // OAuth2 관련 엔드포인트 우선 처리
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

        // Authorization Server 전용 Configurer 생성
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        // authorize/token/jwks 엔드포인트 자동 등록
        http
                .securityMatcher("/oauth2/**", "/.well-known/**", "/jwks/**")
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

        return http.build();



    }

    /**
     * 일반 로그인 / 폼 처리용 SecurityFilterChain
     */
    @Bean
    @Order(2) // 일반 요청은 두 번째 체인으로 처리
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic(basicConfigurer -> basicConfigurer.disable() )
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers( "/login", "/css/**", "/js/**", "/images/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")               // 커스텀 로그인 페이지
                        .loginProcessingUrl("/login")      // 로그인 POST 엔드포인트
                        .defaultSuccessUrl("/oauth2/authorize", true)
                        .usernameParameter("email")
                        .passwordParameter("password")
                        .failureUrl("/login?error=true")
                        .permitAll()
                )

                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                )
//                .csrf(csrf -> csrf
//                        .ignoringRequestMatchers("/oauth2/token") // token endpoint는 stateless
//                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
