package com.gearfirst.backend.api.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {
//
//    private final Key key;
//    private final long accessValidity;
//    private final long refreshValidity;
//
//    public JwtTokenProvider(
//            @Value("${jwt.secret}") String secret,
//            @Value("${jwt.access-token-expiration}") long accessValidity,
//            @Value("${jwt.refresh-token-expiration}") long refreshValidity
//    ) {
//        this.key = Keys.hmacShaKeyFor(secret.getBytes());
//        this.accessValidity = accessValidity;
//        this.refreshValidity = refreshValidity;
//    }
//
//    public String createAccessToken(Long authId, String email) {
//        return createToken(authId, email, accessValidity, "access");
//    }
//
//    public String createRefreshToken(Long authId, String email) {
//        return createToken(authId, email, refreshValidity, "refresh");
//    }
//
//    private String createToken(Long authId, String email, long validity, String tokenType){
//        Date now = new Date();
//        return Jwts.builder()
//                .setSubject(String.valueOf(authId))
//                .claim("email",email)
//                .claim("type",tokenType)
//                .setIssuedAt(now)
//                .setExpiration(new Date(now.getTime() + validity))
//                .signWith(key, SignatureAlgorithm.HS512)
//                .compact();
//    }
//
//    public Claims parseClains(String token){
//        return Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }

}
