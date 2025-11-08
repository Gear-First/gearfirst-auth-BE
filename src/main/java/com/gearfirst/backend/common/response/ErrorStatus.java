package com.gearfirst.backend.common.response;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public enum ErrorStatus {
    /** 400 BAD_REQUEST */
    VALIDATION_REQUEST_MISSING_EXCEPTION(HttpStatus.BAD_REQUEST, "요청 값이 입력되지 않았습니다."),

    /** 401 UNAUTHORIZED */
    USER_UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "인증되지 않은 사용자입니다."),

    /** 404 NOT_FOUND */
    NOT_FOUND_USER_EXCEPTION(HttpStatus.NOT_FOUND, "존재하지 않는 사용자 입니다."),

    /** 409 CONFLICT */
    DUPLICATE_EMAIL_EXCEPTION(HttpStatus.CONFLICT, "이미 존재하는 이메일입니다."),
    ESSENTIAL_USERID_EXCEPTION(HttpStatus.CONFLICT, "userId는 필수 입니다."),
    /** 500 SERVER_ERROR */
    FAIL_SIGNUP(HttpStatus.INTERNAL_SERVER_ERROR,"회원가입에 실패하였습니다."),
    /** 502 BAD_GATEWAY */
    USER_SERVER_INVALID_RESPONSE(HttpStatus.BAD_GATEWAY, "User 서버 응답이 유효하지 않습니다."),
    ;

    private final HttpStatus httpStatus;
    private final String message;

    public int getStatusCode() {
        return this.httpStatus.value();
    }
}
