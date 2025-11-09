package com.gearfirst.backend.api.auth.controller;

import com.gearfirst.backend.api.auth.dto.ChangePasswordRequest;
import com.gearfirst.backend.api.auth.dto.CreateAccount;
import com.gearfirst.backend.api.auth.dto.RegenerateTempPasswordRequest;
import com.gearfirst.backend.api.auth.service.AuthService;
import com.gearfirst.backend.common.response.ApiResponse;
import com.gearfirst.backend.common.response.SuccessStatus;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "auth", description = "인증 API 입니다.")
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "회원가입 API", description = "회원가입을 진행합니다.")
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> createAccount(@Valid @RequestBody CreateAccount request) {
        authService.createAccount(request);
        return ApiResponse.success_only(SuccessStatus.CREATE_SIGNUP_SUCCESS);
    }

    @Operation(summary = "비밀번호 변경 API", description = "비밀번호 변경을 진행합니다.")
    @PostMapping("/change-password/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(request);
        return ApiResponse.success_only(SuccessStatus.CHANGE_PASSWORD_SUCCESS);
    }
    @Operation(summary = "임시 비밀번호 새로 발급 API", description = "임시비밀번호를 개인 메일로 다시 발송합니다..")
    @PostMapping("/regenerate-temp-password")
    public ResponseEntity<ApiResponse<Void>> regenerateTempPassword(@RequestBody RegenerateTempPasswordRequest request) {
        authService.regenerateTempPassword(request.getEmail(),request.getPersonalEmail());
        return ApiResponse.success_only(SuccessStatus.CREATE_TEMP_PASSWORD_SUCCESS);
    }

    @Operation(summary = "유저 삭제 API", description = "user서버가 호출하는 api로 auth에 존재하는 회원을 삭제합니다.")
    @PostMapping("/delete")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@RequestBody Long userId) {
        authService.deleteUser(userId);
        return ApiResponse.success_only(SuccessStatus.DELETE_USER_SUCCESS);
    }



}
