package com.gearfirst.backend.common.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {
    private final PasswordEncoder passwordEncoder;
    /**
     * 클라이언트 등록
     * 인가코드, 리프래시토큰, PKCE 지원 설정
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        //클라이언트를 구분하기 위한 고유 ID

        //1. 웹 클라이언트 (React, Vue 등)
        RegisteredClient webClient = RegisteredClient.withId("gearfirst-client-id")
                .clientId("gearfirst-client") //프론트엔드 앱 id
                .clientSecret(passwordEncoder.encode("secret"))
                //.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) //OAuth2 인증 방식
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://gearfirst-fe.vercel.app/auth/callback")   // //인가 코드 발급 후 돌아올 주소 (프론트 주소)
                .redirectUri("http://localhost:5173/auth/callback")
                .postLogoutRedirectUri("http://localhost:5173/login") // 로그아웃 후 돌아올 주소 추가
                .postLogoutRedirectUri("https://gearfirst-fe.vercel.app/login")
                .scope("openid")        //클라이언트가 요청 가능한 접근 범위
                .scope("email")
                .scope("offline_access")
                //토큰 관련 정책
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false) //rotation
                        .build())
                //클라이언트 정책
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false) // “이 앱이 정보에 접근하도록 허용하시겠습니까?” 창 비활성화
                        .requireProofKey(true)
                        .build())
                .build();


        // 2. 네이티브 앱 클라이언트 (Android / iOS)
        RegisteredClient nativeAppClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("gearfirst-client-mobile")
                .clientSecret(passwordEncoder.encode("secret"))
                //.clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // 시크릿 없음
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // RFC 8252에 따라 loopback 또는 custom scheme redirect 허용
                //.redirectUri("com.gearfirst.app://callback")
                // 로컬 테스트용
                .redirectUri("gearfirst://callback") // Android 에뮬레이터 & iOS 시뮬레이터 & 실제 기기 테스트 (Mac IP)
                .scope("openid")
                .scope("email")
                .scope("offline_access")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true) // PKCE 필수
                        .build())
                .build();
        //메모리 기반 저장소 TODO: 운영 시 DB 기반 Repository로 변경 필요
        return new InMemoryRegisteredClientRepository(webClient, nativeAppClient);
    }

    /**
     * Authorization Server 세부 설정
     * issuer(토큰 발급자) URI 지정
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                //.issuer("http://localhost:8084") // JWT iss 값으로 사용됨
                .issuer("http://34.120.215.23/auth") // JWT iss 값으로 사용됨 배포용
                .build();
    }
}
