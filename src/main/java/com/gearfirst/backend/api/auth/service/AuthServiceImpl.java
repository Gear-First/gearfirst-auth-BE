package com.gearfirst.backend.api.auth.service;

import com.gearfirst.backend.api.auth.dto.ChangePasswordRequest;
import com.gearfirst.backend.api.auth.dto.SignupRequest;
import com.gearfirst.backend.api.auth.entity.Auth;
import com.gearfirst.backend.api.auth.respository.AuthRepository;
import com.gearfirst.backend.api.infra.client.UserClient;
import com.gearfirst.backend.api.infra.dto.UserLoginResponse;
import com.gearfirst.backend.api.infra.dto.UserProfileRequest;
import com.gearfirst.backend.common.exception.KnownBusinessException;
import com.gearfirst.backend.common.exception.NotFoundException;
import com.gearfirst.backend.common.response.ApiResponse;
import com.gearfirst.backend.common.response.ErrorResponse;
import com.gearfirst.backend.common.response.ErrorStatus;
import com.gearfirst.backend.common.result.ActResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final PasswordEncoder passwordEncoder;
    private final AuthRepository authRepository;
    private final UserClient userClient;

    /**
     * 회원가입 - Auth 저장 후 User 서버에 사용자 프로필 등록
     *  - User 서버 실패 시 3회 재시도
     *  - 실패 시 Auth 롤백
     */
    @Override
    public ActResult<Void> signup(SignupRequest request) {
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        return ActResult.of(() -> {
            // 이메일 중복 체크
            if(authRepository.findByEmail(request.getEmail()).isPresent()){
                throw new KnownBusinessException(ErrorStatus.DUPLICATE_EMAIL_EXCEPTION.getMessage());
            }

            UserProfileRequest profileRequest = new UserProfileRequest(
                    request.getEmail(),
                    request.getName(),
                    request.getPhoneNum(),
                    request.getRank(),
                    request.getRegionId(),
                    request.getWorkTypeId()
            );

            ActResult<Long> userResult = callUserServerWithRetry(profileRequest, 3);

            //  User 서버 실패 시 롤백
            if (userResult.getResultType() != ActResult.ResultType.SUCCESS) {
                System.out.println("User 서버 등록 실패 -> Auth 롤백");
                throw new KnownBusinessException("User 서버 등록 실패로 회원가입 롤백됨");
            }
            Long userId = ((ActResult.Success<Long>) userResult).getData();

            Auth auth = Auth.builder()
                    .email(request.getEmail())
                    .password(encodedPassword)
                    .build();
            System.out.println("회원 가입시 auth 서버 저장완료: {} " + auth.getEmail());

            auth.linkToUser(userId);
            try{
                authRepository.save(auth);
                System.out.println(" 회원가입 전체 성공");
            } catch (Exception e){
                // Auth 저장 실패 시 User 서버에 보상 트랜잭션 호출
                //TODO: userClient.rollbackUser(userId);
                System.out.println("UserId 연동 전 auth 저장 실패 -> 롤백");
                throw new KnownBusinessException("Auth 저장 실패로 회원가입 롤백됨");
            }

            return null;
        });

    }

    /**
     * User 서버 호출 재시도 로직
     */
    private ActResult<Long> callUserServerWithRetry(UserProfileRequest request, int maxRetry) {
        int attempts = 0;
        ActResult<Long> result;

        do {
            attempts++;
            log.info("User 서버 등록 시도 {}회차" + attempts);

            result = ActResult.of(() -> {
                ApiResponse<UserLoginResponse> response = userClient.registerUser(request);
                Long userId = response.getData().getUserId();
                return userId;
            });



            if (result.getResultType() == ActResult.ResultType.SUCCESS) {
                return result;
            }

            log.error("User 서버 등록 실패 ({}회차)" + attempts);

            // 재시도 사이에 잠시 대기 (optional)
            try {
                Thread.sleep(1000L);
            } catch (InterruptedException ignored) { }

        } while (attempts < maxRetry);


        // 최종 실패
        log.error("User 서버 등록 3회 실패 - UNKNOWN 상태로 반환");
        return ActResult.failure(new ErrorResponse(new KnownBusinessException("User 서버 호출 3회 실패")));
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
