package com.gearfirst.backend.api.auth.service;


import com.gearfirst.backend.api.auth.dto.ChangePasswordRequest;
import com.gearfirst.backend.api.auth.dto.CreateAccount;

public interface AuthService {
    void createAccount(CreateAccount request);
    void changePassword(ChangePasswordRequest request);
    void regenerateTempPassword(String email,String personalEmail);
    void deleteUser(Long userId);
}