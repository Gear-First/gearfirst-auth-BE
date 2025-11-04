package com.gearfirst.backend.api.auth.service;


import com.gearfirst.backend.api.auth.dto.ChangePasswordRequest;
import com.gearfirst.backend.api.auth.dto.SignupRequest;
import com.gearfirst.backend.common.result.ActResult;

public interface AuthService {
    void signup(SignupRequest request);
    void changePassword(ChangePasswordRequest request);
}