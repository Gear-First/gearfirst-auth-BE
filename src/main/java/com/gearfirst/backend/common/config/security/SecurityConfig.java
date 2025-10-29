package com.gearfirst.backend.common.config.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public RequestCache requestCacheBean() { // 공용 Bean으로 등록
        return new CustomRequestCache();
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

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                .requestCache(c -> c.requestCache(requestCacheBean()))

                //.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .securityMatcher(endpointsMatcher)
                //.with(authorizationServerConfigurer, Customizer.withDefaults())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer.oidc(Customizer.withDefaults()) // OIDC 켜기
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/.well-known/openid-configuration", "/.well-known/jwks.json").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        http.addFilterAfter(new OAuth2DebugFilter(), SecurityContextHolderFilter.class);

        return http.build();
    }

    /**
     * 일반 로그인 / 폼 처리용 SecurityFilterChain
     */
    @Bean
    @Order(2) // 일반 요청은 두 번째 체인으로 처리
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .addFilterAfter((request, response, chain) -> {
                    var auth = SecurityContextHolder.getContext().getAuthentication();
                    System.out.println(" [Auth Filter] Principal: " +
                            (auth != null ? auth.getName() : "null"));
                    chain.doFilter(request, response);
                }, UsernamePasswordAuthenticationFilter.class)
                .requestCache(c -> c.requestCache(requestCacheBean()))

                .cors(Customizer.withDefaults())
                .httpBasic(basicConfigurer -> basicConfigurer.disable() )
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers( "/login", "/css/**", "/js/**", "/images/**", "/.well-known/**",  "/error","/favicon.ico" ).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")               // 커스텀 로그인 페이지
                        .loginProcessingUrl("/login")      // 로그인 POST 엔드포인트
                        .usernameParameter("email")
                        .passwordParameter("password")
//                        .successHandler((request, response, authentication) -> {
//                            request.getSession().invalidate(); // 기존 세션 제거
//                        })

                        .failureUrl("/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)



                );


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
        config.setAllowedOrigins(Collections.singletonList("http://127.0.0.1:8080"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(Collections.singletonList("*"));
        config.setExposedHeaders(Collections.singletonList("*"));
        config.setAllowCredentials(true);

        var source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }


}
