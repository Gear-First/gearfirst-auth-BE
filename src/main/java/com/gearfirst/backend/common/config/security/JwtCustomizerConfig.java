package com.gearfirst.backend.common.config.security;

import com.gearfirst.backend.api.auth.entity.Auth;
import com.gearfirst.backend.api.auth.respository.AuthRepository;
import com.gearfirst.backend.api.infra.client.UserClient;
import com.gearfirst.backend.api.infra.dto.UserInfoRequest;
import com.gearfirst.backend.api.infra.dto.UserResponse;
import com.gearfirst.backend.common.exception.NotFoundException;
import com.gearfirst.backend.common.response.ApiResponse;
import com.gearfirst.backend.common.response.ErrorStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

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
                String email = principal.getName();

                // authRepository에서 사용자 찾기
                Auth auth = authRepository.findByEmail(email)
                        .orElseThrow(() -> new NotFoundException(ErrorStatus.NOT_FOUND_USER_EXCEPTION.getMessage()));
                Long userId = auth.getAuthId();

                //  User 서버 호출 (ApiResponse로 받기)
                ApiResponse<UserResponse> response = userClient.getUser(userId);

                //  ApiResponse에서 실제 UserResponse 객체 꺼내기
                UserResponse user = response.getData();

                //  클레임에 커스텀 값 추가
                context.getClaims().claim("sub", user.getId());
                context.getClaims().claim("name", user.getName());
                context.getClaims().claim("rank",user.getRank());
                context.getClaims().claim("region", user.getRegion());
                context.getClaims().claim("work_type", user.getWorkType());
            }
        };
    }
}
