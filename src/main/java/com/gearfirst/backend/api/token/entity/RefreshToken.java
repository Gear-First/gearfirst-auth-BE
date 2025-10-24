package com.gearfirst.backend.api.token.entity;

import com.gearfirst.backend.api.auth.entity.Auth;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter @Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Table(name = "refresh_token")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name ="refresh_token_id")
    private Long refreshTokenId;

    @Column(name = "refresh_token", length = 500, nullable = false)
    private String refreshToken;

    @Column(name="expired_at", nullable = false)
    private LocalDateTime expiredAt;        //만료시간

    @Column(name = "revoked", nullable = false)
    private boolean revoked;                //폐기여부

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="auth_id")
    private Auth auth;

    public void revoke() { this.revoked = true; }

}
