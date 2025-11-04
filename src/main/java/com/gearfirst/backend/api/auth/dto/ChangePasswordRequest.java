package com.gearfirst.backend.api.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class ChangePasswordRequest {
    private Long userId; // TODO: 임시로 사용 (인가 구현 전)
    @NotBlank(message = "현재 비밀번호는 필수입니다.")
    String currentPassword;
    @NotBlank(message = "새 비밀번호는 필수입니다.")
    String newPassword;
    @NotBlank(message = "비밀번호 확인은 필수입니다.")
    String confirmPassword;
}
