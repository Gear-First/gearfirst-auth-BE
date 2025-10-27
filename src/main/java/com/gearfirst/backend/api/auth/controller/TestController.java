package com.gearfirst.backend.api.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth-test")
public class TestController {
    @GetMapping("/login-success")
    @ResponseBody
    public String loginSuccess(@RequestParam(required = false) String code,
                               @RequestParam(required = false) String error,
                               @RequestParam(required = false, name = "error_description") String desc) {
        if (error != null) {
            System.out.println(" 로그인 실패: " + error);
            return " 로그인 실패 : " + error + "<br>" + desc;
        }
        // 콘솔에 인가 코드 출력
        System.out.println("============================================");
        System.out.println(" 인가 코드 발급 성공!");
        System.out.println(" Code: " + code);
        System.out.println("============================================");
        return "인가 코드 : " + code;
    }
    @GetMapping("/me")
    public String whoAmI(Authentication authentication) {
        System.out.println("👤 현재 사용자: " + authentication.getName());
        System.out.println("🔐 권한: " + authentication.getAuthorities());
        return authentication.getAuthorities().toString();
    }
}
