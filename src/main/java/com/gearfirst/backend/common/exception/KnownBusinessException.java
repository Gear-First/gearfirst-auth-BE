package com.gearfirst.backend.common.exception;

import org.springframework.http.HttpStatus;

public class KnownBusinessException extends BaseException{
    public KnownBusinessException() {
        super(HttpStatus.BAD_REQUEST);
    }
    public KnownBusinessException(String responseMessage) {
        super(HttpStatus.BAD_REQUEST, responseMessage);
    }
}
