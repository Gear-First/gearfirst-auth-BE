package com.gearfirst.backend.api.auth.controller;

import com.gearfirst.backend.api.auth.dto.ChangePasswordRequest;
import com.gearfirst.backend.api.auth.dto.SignupRequest;
import com.gearfirst.backend.api.auth.service.AuthService;
import com.gearfirst.backend.common.response.ApiResponse;
import com.gearfirst.backend.common.response.SuccessStatus;
import com.gearfirst.backend.common.result.ActResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@Tag(name = "auth", description = "인증 API 입니다.")
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "회원가입 API", description = "회원가입을 진행합니다.")
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signup(@Valid  @RequestBody SignupRequest request) {
        ActResult<Void> result = authService.signup(request);

        return switch (result.getResultType()) {
            case SUCCESS -> ApiResponse.success_only(SuccessStatus.CREATE_SIGNUP_SUCCESS);
            case FAILURE -> {
                String errorMessage = ((ActResult.Failure<Void>) result).getErrorResponse().getMessage();
                yield ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.fail(HttpStatus.BAD_REQUEST.value(), errorMessage));
            }
            case UNKNOWN -> {
                String errorMessage = ((ActResult.Unknown<Void>) result).getErrorResponse().getMessage();
                yield ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.fail(HttpStatus.INTERNAL_SERVER_ERROR.value(), errorMessage));
            }
        };
    }

    @Operation(summary = "비밀번호 변경 API", description = "비밀번호 변경을 진행합니다.")
    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(request);
        return ApiResponse.success_only(SuccessStatus.CHANGE_PASSWORD_SUCCESS);
    }

}
