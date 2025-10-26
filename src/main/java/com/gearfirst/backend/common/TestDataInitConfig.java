package com.gearfirst.backend.common;

import com.gearfirst.backend.api.auth.entity.Auth;
import com.gearfirst.backend.api.auth.entity.AuthStatus;
import com.gearfirst.backend.api.auth.respository.AuthRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class TestDataInitConfig {

    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    public void init() {
        // 이미 데이터가 있으면 중복 삽입 방지
        if (authRepository.findByEmail("test@gearfirst.com").isPresent()) {
            return;
        }

        Auth user = Auth.builder()
                .userId(1001L)
                .email("test@gearfirst.com")
                .password(passwordEncoder.encode("1234"))
                .status(AuthStatus.ACTIVE)
                .isFirstLogin(true)
                .build();

        authRepository.save(user);
        System.out.println("✅ Test account created: test@gearfirst.com / 1234");
    }
}
