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
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.security.SecureRandom;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final PasswordEncoder passwordEncoder;
    private final AuthRepository authRepository;
    private final MailService mailService;

    //이메일 복구되면 바꿀 예정
    @Transactional
    @Override
    public void createAccount(CreateAccount request) {
        String tempPassword = RandomStringUtils.random(10, 0, 0, true, true, null, new SecureRandom());
        String encodedPassword = passwordEncoder.encode(tempPassword);
        log.info("tempPassword: {}", tempPassword);


        // 이메일 중복 체크
        if(authRepository.findByEmail(request.getEmail()).isPresent()){
            throw new KnownBusinessException(ErrorStatus.DUPLICATE_EMAIL_EXCEPTION.getMessage());
        }

        Auth auth = Auth.builder()
                .email(request.getEmail())
                .password(encodedPassword)
                .build();
        authRepository.save(auth);

        if(TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    try{
                        //mailService.sendUserRegistrationMail(request.getPersonalEmail(), tempPassword);
                    }catch (Exception e) {
                        log.error("메일 발송 실패 - personalEmail={}, message={}", request.getPersonalEmail(), e.getMessage(), e);
                    }

                }
            });
        } else {
            //mailService.sendUserRegistrationMail(request.getPersonalEmail(), tempPassword);
        }
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

    @Transactional
    @Override
    public void regenerateTempPassword(String email,String personalEmail) {
        Auth auth = authRepository.findByEmail(email)
                .orElseThrow(() -> new NotFoundException(ErrorStatus.NOT_FOUND_USER_EXCEPTION.getMessage()));
        // 새 임시 비밀번호 생성
        String newTempPassword = RandomStringUtils.random(10, 0, 0, true, true, null, new SecureRandom());
        String encoded = passwordEncoder.encode(newTempPassword);

        // 비밀번호 갱신
        auth.updatePassword(encoded);
        authRepository.save(auth);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    //mailService.sendUserRegistrationMail(personalEmail, newTempPassword);
                } catch (Exception e) {
                    throw new IllegalStateException("메일 발송 중 오류가 발생했습니다: " + e.getMessage());
                }
            }
        });
    }
}
