package com.gearfirst.backend.common.config.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);
    private RequestCache requestCache;
    @Bean
    public RequestCache requestCacheBean() { // 공용 Bean으로 등록
        return new CustomRequestCache();
    }
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
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http, RegisteredClientRepository registeredClientRepository) throws Exception {

        // Authorization Server 전용 Configurer 생성
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();
        log.info(" [AuthServerChain] Authorization Server SecurityFilterChain 초기화됨");

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
// authorize/token/jwks 엔드포인트 자동 등록
        http

                //.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                //.with(authorizationServerConfigurer, Customizer.withDefaults())
                .securityMatcher(endpointsMatcher)
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/.well-known/openid-configuration", "/.well-known/jwks.json").permitAll()
                        .anyRequest().authenticated()
                )
                //.requestCache(requestCache -> requestCache.disable())
                .requestCache(c -> c.requestCache(requestCacheBean()))
                //.exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")) )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                //.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                //.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/token")); // token 요청은 제외
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .formLogin(form -> form.loginPage("/login").permitAll())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        http
                .addFilterAfter(new OAuth2DebugFilter(), SecurityContextHolderFilter.class);
        log.debug(" [AuthServerChain] AuthorizationServerConfigurer 활성화 완료");
        return http.build();


    }

    /**
     * 일반 로그인 / 폼 처리용 SecurityFilterChain
     */
    @Bean
    @Order(2) // 일반 요청은 두 번째 체인으로 처리
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        log.info(" [DefaultChain] Form Login SecurityFilterChain 초기화됨");
        http
                .addFilterAfter((request, response, chain) -> {
                    var auth = SecurityContextHolder.getContext().getAuthentication();
                    System.out.println(" [Auth Filter] Principal: " +
                            (auth != null ? auth.getName() : "null"));
                    chain.doFilter(request, response);
                }, UsernamePasswordAuthenticationFilter.class)
                .httpBasic(basicConfigurer -> basicConfigurer.disable() )
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers( "/login", "/css/**", "/js/**", "/images/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")               // 커스텀 로그인 페이지
                        .loginProcessingUrl("/login")      // 로그인 POST 엔드포인트
                        .usernameParameter("email")
                        .passwordParameter("password")

                        .failureUrl("/login?error=true")
                        .permitAll()
                )

                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                )
                // 커스터마이징된 RequestCache 등록
                .requestCache(c -> c.requestCache(requestCacheBean()));
        log.debug("🔍 [DefaultChain] Form Login 설정 완료");
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        var config = new org.springframework.web.cors.CorsConfiguration();
        config.setAllowedOrigins(Collections.singletonList("http://localhost:5173"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(Collections.singletonList("*"));
        config.setExposedHeaders(Collections.singletonList("*"));
        config.setAllowCredentials(true);

        var source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }


}
