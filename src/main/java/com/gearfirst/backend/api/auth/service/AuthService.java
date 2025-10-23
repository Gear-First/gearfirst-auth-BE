package com.gearfirst.backend.api.auth.service;

import com.gearfirst.backend.api.auth.dto.LoginRequest;
import com.gearfirst.backend.api.auth.dto.TokenResponse;
import com.gearfirst.backend.api.auth.entity.Auth;
import com.gearfirst.backend.api.auth.respository.AuthRepository;
import com.gearfirst.backend.api.token.entity.RefreshToken;
import com.gearfirst.backend.api.token.repository.RefreshTokenRepository;
import com.gearfirst.backend.common.exception.NotFoundException;
import com.gearfirst.backend.common.exception.UnAuthorizedException;
import com.gearfirst.backend.common.response.ErrorStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthRepository authRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private PasswordEncoder passwordEncoder;

//    public TokenResponse login(LoginRequest req){
//        Auth auth = authRepository.findByEmail(req.getEmail())
//                .orElseThrow(()-> new UnAuthorizedException(ErrorStatus.USER_UNAUTHORIZED.getMessage()));
//
//        if(!passwordEncoder.matches(req.getPassword(), auth.getPassword()))
//            throw new UnAuthorizedException(ErrorStatus.NOT_FOUND_USER_EXCEPTION.getMessage());
//
//        String access = jwtTokenProvider.createAccessToken(auth.getAuthId(), auth.getEmail());
//        String refresh = jwtTokenProvider.createRefreshToken(auth.getAuthId(), auth.getEmail());
//
//        refreshTokenRepository.save(
//                RefreshToken.builder()
//                        .refreshToken(refresh)
//                        .expiredAt(LocalDateTime.now().plusDays(7))
//                        .revoked(false)
//                        .auth(auth)
//                        .build()
//        );
//
//        auth.updateLastLogin();
//        return new TokenResponse(access, refresh);
//    }

}
