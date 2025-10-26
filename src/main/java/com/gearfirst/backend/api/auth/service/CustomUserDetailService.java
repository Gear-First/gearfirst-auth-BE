package com.gearfirst.backend.api.auth.service;

import com.gearfirst.backend.api.auth.entity.Auth;
import com.gearfirst.backend.api.auth.respository.AuthRepository;
import com.gearfirst.backend.common.exception.NotFoundException;
import com.gearfirst.backend.common.exception.UnAuthorizedException;
import com.gearfirst.backend.common.response.ErrorStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final AuthRepository authRepository;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Auth auth = authRepository.findByEmail(email)
                .orElseThrow(()-> new UnAuthorizedException(ErrorStatus.NOT_FOUND_USER_EXCEPTION.getMessage()));
        return org.springframework.security.core.userdetails.User.builder()
                .username(auth.getEmail())
                .password(auth.getPassword())
                .build();
    }
}
