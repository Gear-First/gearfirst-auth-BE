package com.gearfirst.backend.api.auth.dto;

import lombok.Getter;

@Getter
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
}
