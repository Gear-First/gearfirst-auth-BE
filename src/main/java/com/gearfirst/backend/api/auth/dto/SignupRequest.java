package com.gearfirst.backend.api.auth.dto;

import lombok.Getter;

@Getter
public class SignupRequest {
    private String email;
    private String password;
    private String name;
    private String phoneNum;
    private Long regionId;
    private String rank;
    private Long workTypeId;
}
