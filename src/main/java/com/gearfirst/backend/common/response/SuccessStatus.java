package com.gearfirst.backend.common.response;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public enum SuccessStatus {
    /** 200 SUCCESS */
    SEND_SAMPLE_SUCCESS(HttpStatus.OK,"샘플 조회 성공"),
    CHANGE_PASSWORD_SUCCESS(HttpStatus.OK, "비밀번호 변경 성공"),

    /** 201 CREATED */
    CREATE_SAMPLE_SUCCESS(HttpStatus.CREATED, "샘플 등록 성공"),
    CREATE_ACCESS_TOKEN_SUCCESS(HttpStatus.CREATED, "토큰 발급 성공"),
    CREATE_SIGNUP_SUCCESS(HttpStatus.CREATED, "회원 가입 성공"),
    CREATE_TEMP_PASSWORD_SUCCESS(HttpStatus.CREATED, "임시 비밀번호 발송 성공"),



    ;

    private final HttpStatus httpStatus;
    private final String message;

    public int getStatusCode() {
        return this.httpStatus.value();
    }
}
