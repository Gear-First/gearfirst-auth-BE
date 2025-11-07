package com.gearfirst.backend.api.auth.entity;

import com.gearfirst.backend.common.entity.BaseTimeEntity;
import com.gearfirst.backend.common.exception.KnownBusinessException;
import com.gearfirst.backend.common.exception.UnAuthorizedException;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

@Entity
@Getter @Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Table(name = "auth")
public class Auth extends BaseTimeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name ="auth_id")
    private Long authId;

    @Column(name = "user_id", unique = true)
    private Long userId;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false, length = 255)
    private String password;

    @Enumerated(EnumType.STRING)
    private AuthStatus status;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;      //마지막 로그인 시간
    @Column(name = "is_first_login")
    private Boolean isFirstLogin;           //첫 로그인 여부


    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
        this.isFirstLogin = true;
        this.status = this.status == null ? AuthStatus.ACTIVE : this.status;
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    public void updateLastLogin() {
        this.lastLoginAt = LocalDateTime.now();
    }


    public void verifyPassword(String rawPassword, PasswordEncoder encoder) {
        if (!encoder.matches(rawPassword, this.password)) {
            throw new UnAuthorizedException("비밀번호가 잘못되었습니다. 다시 입력해주세요.");
        }
    }

    public void changePassword(String newPassword, PasswordEncoder encoder) {
        this.password = encoder.encode(newPassword);
    }
    public void updatePassword(String newEncodedPassword) {
        this.password = newEncodedPassword;
    }

    public void linkToUser(Long userId) {
        if (this.userId != null) {
            throw new KnownBusinessException("이미 userId가 등록된 계정입니다.");
        }
        this.userId = userId;
    }

}
