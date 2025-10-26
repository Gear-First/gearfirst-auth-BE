package com.gearfirst.backend.common.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
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
        RegisteredClient gearFirstClient = RegisteredClient.withId(UUID.randomUUID().toString())
                //클라이언트 식별 정보
                .clientId("gearfirst-client") //프론트엔드 앱 id
                //.clientSecret("{noop}secret") // 개발 단계에서는 NoOp (운영에선 BCrypt!)
                //.clientSecret(passwordEncoder.encode("secret")) // 개발 단계에서는 NoOp (운영에선 BCrypt!)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                //OAuth2 인증 방식
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                //인가 코드 발급 후 돌아올 주소 (프론트 주소)
                //TODO: .redirectUri("https://app.gearfirst.com/login/callback") // 인가 코드 받은 뒤 리디렉션 URI
                .redirectUri("http://localhost:5173/auth/callback")
                //.redirectUri("http://localhost:8084/auth/callback") // 테스트용 리디렉션 URI

                //클라이언트가 요청 가능한 접근 범위
                .scope("user")
                .scope("inventory")
                .scope("order")
                //토큰 관련 정책
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false)
                        .build())
                //클라이언트 정책
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false) // “이 앱이 정보에 접근하도록 허용하시겠습니까?” 창 비활성화
                        .requireProofKey(false) // PKCE 필수(true) TODO: 프론트 엔드가 붙으면 활성화 예정
                        .build())
                .build();
        //메모리 기반 저장소
        return new InMemoryRegisteredClientRepository(gearFirstClient);
    }

    /**
     * Authorization Server 세부 설정
     * issuer(토큰 발급자) URI 지정
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8084") // JWT iss 값으로 사용됨
                .build();
    }
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings(
//            @Value("${spring.security.oauth2.authorizationserver.issuer}") String issuer) {
//        return AuthorizationServerSettings.builder()
//                .issuer(issuer)
//                .authorizationEndpoint("/oauth2/authorize")
//                .tokenEndpoint("/oauth2/token")
//                .jwkSetEndpoint("/.well-known/jwks.json")
//                .build();
//    }


}
