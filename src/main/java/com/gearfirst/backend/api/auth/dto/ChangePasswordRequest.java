package com.gearfirst.backend.api.auth.dto;

import lombok.Getter;

@Getter
public class ChangePasswordRequest {
    private Long userId; // TODO: 임시로 사용 (인가 구현 전)
    String currentPassword;
    String newPassword;
    String confirmPassword;
}
