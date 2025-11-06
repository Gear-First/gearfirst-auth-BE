package com.gearfirst.backend.api.auth.dto;

import lombok.Getter;

@Getter
public class CreateAccount {
    private String email;
    private String password;
}
