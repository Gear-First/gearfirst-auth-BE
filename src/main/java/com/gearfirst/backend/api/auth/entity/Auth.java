package com.gearfirst.backend.api.auth.entity;

import com.gearfirst.backend.common.entity.BaseTimeEntity;
import jakarta.persistence.*;
import lombok.*;

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

    @Column(nullable = false)
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

}
