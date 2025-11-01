package com.gearfirst.backend.api.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;

//형식 검증은 request단계에서 처리, 의미검증(비밀번호존재 여부 등)은 service단계에서 처리
@Getter
public class SignupRequest {
    @Email @NotBlank
    private String email;
    @NotBlank
//    @Pattern(
//            regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,20}$",
//            message = "비밀번호는 8~20자, 영문 대소문자, 숫자, 특수문자를 모두 포함해야 합니다."
//    )
    private String password;
    @NotBlank(message = "이름은 필수입니다.")
    private String name;
    @Pattern(regexp = "^[0-9]{10,11}$", message = "전화번호는 숫자 10~11자리여야 합니다.")
    private String phoneNum;
    private Long regionId;
    private String rank;
    private Long workTypeId;
}
