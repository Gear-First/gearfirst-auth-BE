package com.gearfirst.backend.api.token.dto;

import lombok.Getter;

@Getter
public class RefreshTokenRequest {
    private String refreshToken;
}
