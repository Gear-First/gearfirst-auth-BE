package com.gearfirst.backend.api.auth.service;

import com.gearfirst.backend.api.auth.dto.ChangePasswordRequest;
import com.gearfirst.backend.api.auth.dto.CreateAccount;
import com.gearfirst.backend.api.auth.dto.SignupRequest;
import com.gearfirst.backend.api.auth.entity.Auth;
import com.gearfirst.backend.api.auth.repository.AuthRepository;
import com.gearfirst.backend.api.infra.client.UserClient;
import com.gearfirst.backend.api.infra.dto.UserLoginResponse;
import com.gearfirst.backend.api.infra.dto.UserProfileRequest;
import com.gearfirst.backend.api.mail.MailService;
import com.gearfirst.backend.common.exception.KnownBusinessException;
import com.gearfirst.backend.common.exception.NotFoundException;
import com.gearfirst.backend.common.response.ApiResponse;
import com.gearfirst.backend.common.response.ErrorResponse;
import com.gearfirst.backend.common.response.ErrorStatus;
import com.gearfirst.backend.common.result.ActResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final PasswordEncoder passwordEncoder;
    private final AuthRepository authRepository;
    private final MailService mailService;

    @Transactional
    @Override
    public void createAccount(CreateAccount request) {
        String tempPassword = RandomStringUtils.random(10, true, true);
        String encodedPassword = passwordEncoder.encode(tempPassword);

        // 이메일 중복 체크
        if(authRepository.findByEmail(request.getEmail()).isPresent()){
            throw new KnownBusinessException(ErrorStatus.DUPLICATE_EMAIL_EXCEPTION.getMessage());
        }
        //  이메일 발송
        try {
            mailService.sendUserRegistrationMail(request.getPersonalEmail(), tempPassword);
        } catch (Exception e) {
            throw new IllegalStateException("메일 발송 중 오류가 발생했습니다: " + e.getMessage());
        }

        Auth auth = Auth.builder()
                .email(request.getEmail())
                .password(encodedPassword)
                .build();
        authRepository.save(auth);
    }

    @Transactional
    @Override
    public void changePassword(ChangePasswordRequest request) {
        Auth auth = authRepository.findByUserId(request.getUserId())
                .orElseThrow(() -> new NotFoundException(ErrorStatus.NOT_FOUND_USER_EXCEPTION.getMessage()));
        auth.verifyPassword(request.getCurrentPassword(), passwordEncoder);
        if(!request.getNewPassword().equals(request.getConfirmPassword())){
            throw new KnownBusinessException("새 비밀번호와 비밀번호 확인이 일치하지 않습니다.");
        }
        auth.changePassword(request.getNewPassword(), passwordEncoder);
    }
}
