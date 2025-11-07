package com.gearfirst.backend.api.auth.service;


import com.gearfirst.backend.api.auth.dto.ChangePasswordRequest;
import com.gearfirst.backend.api.auth.dto.CreateAccount;
import com.gearfirst.backend.api.auth.dto.SignupRequest;
import com.gearfirst.backend.common.result.ActResult;

public interface AuthService {
    //void createAccount(CreateAccount request);
    String createAccount(CreateAccount request);
    void changePassword(ChangePasswordRequest request);
    void regenerateTempPassword(String email,String personalEmail);
}