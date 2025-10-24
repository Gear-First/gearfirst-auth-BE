package com.gearfirst.backend.common.config.security;

import com.gearfirst.backend.api.auth.entity.Auth;
import com.gearfirst.backend.api.auth.respository.AuthRepository;
import com.gearfirst.backend.api.infra.client.UserClient;
import com.gearfirst.backend.api.infra.dto.UserLoginRequest;
import com.gearfirst.backend.api.infra.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Collection;

@Configuration
@RequiredArgsConstructor
public class JwtCustomizerConfig {
    private final UserClient userClient;
    private final AuthRepository authRepository;

    /**
     * JWT 발급 시 커스텀 클레임 추가
     * - sub: 사용자명 (username)
     * - user_id: DB PK
     * - role: 권한
     * - organization_type: 본사 / 지점 / 창고 구분
     * - organization_id: 조직 PK
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            // Access Token 발급일 때만 동작하도록
            if (context.getTokenType().getValue().equals("access_token")) {

                Authentication principal = context.getPrincipal();
                String username = principal.getName();

//                // User 서버에 사용자 정보 요청
//                UserResponse user = userClient.verifyUser(
//                        new UserLoginRequest(username, null) // JWT 발급 시 비밀번호는 이미 검증 완료
//                );
//
//                //  클레임에 커스텀 값 추가
//                context.getClaims().claim("sub", username);
//                context.getClaims().claim("user_id", user.getUserId());
//                context.getClaims().claim("role","ROLE_"+ user.getRole());
//                context.getClaims().claim("organization_type", user.getOrganizationType());
//                context.getClaims().claim("organization_id", user.getOrganizationId());

                // Auth 서버 DB에서 사용자 정보 조회
                Auth auth = authRepository.findByEmail(username)
                        .orElseThrow(() -> new RuntimeException("User not found"));

                // 권한 정보 추출 (CustomUserDetailService에서 설정한 ROLE_ENGINEER)
                Collection<? extends GrantedAuthority> authorities = principal.getAuthorities();
                String role = authorities.stream()
                        .findFirst()
                        .map(GrantedAuthority::getAuthority)
                        .orElse("ROLE_USER");

                //  클레임에 커스텀 값 추가
                context.getClaims().claim("sub", username);
                context.getClaims().claim("user_id", auth.getUserId());
                context.getClaims().claim("role", role);  // ROLE_ENGINEER 형식

                // 콘솔에 JWT 생성 로그 출력
                System.out.println("============================================");
                System.out.println(" JWT 토큰 생성 완료!");
                System.out.println("   사용자: " + username);
                System.out.println("   user_id: " + auth.getUserId());
                System.out.println("   role: " + role);
                System.out.println("============================================");

            }
        };
    }
}
