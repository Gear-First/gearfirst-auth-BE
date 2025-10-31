package com.gearfirst.backend.api.infra.client;

import com.gearfirst.backend.api.infra.dto.UserLoginResponse;
import com.gearfirst.backend.api.infra.dto.UserProfileRequest;
import com.gearfirst.backend.api.infra.dto.UserResponse;
import com.gearfirst.backend.common.response.ApiResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * TODO:
 *  - 타임아웃: UserClient에 타임아웃 설정 없음 (Spring Cloud OpenFeign 기본값: 연결 10초/읽기 60초 사용)
 *  - 재시도: build.gradle에 재시도 정책 미설정 (Spring 기본값: NEVER_RETRY - 재시도 비활성화)
 *  - 서킷브레이커: Resilience4j/Circuit Breaker 의존성 없음
 *  - 애플리케이션 설정: Feign 클라이언트 커스텀 설정 없음
 */
@FeignClient(name = "user-service", url = "http://localhost:8085")
public interface UserClient {
    //토큰 발급시
    @GetMapping("/api/v1/getUser")
    //UserResponse verifyUser(@RequestBody UserLoginRequest request);
    ApiResponse<UserResponse> getUser(@RequestParam Long userId);

    //회원가입
    @PostMapping("/api/v1/registUser")
    //void createUser(@RequestBody UserProfileRequest request);
    ApiResponse<UserLoginResponse> registUser(@RequestBody UserProfileRequest request);
}
