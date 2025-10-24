package com.gearfirst.backend.api.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TestController {
    @GetMapping("/login-success")
    @ResponseBody
    public String loginSuccess(@RequestParam(required = false) String code,
                               @RequestParam(required = false) String error,
                               @RequestParam(required = false, name = "error_description") String desc) {
        if (error != null) {
            System.out.println("❌ 로그인 실패: " + error);
            return " 로그인 실패 : " + error + "<br>" + desc;
        }

        // 콘솔에 인가 코드 출력
        System.out.println("============================================");
        System.out.println("✅ 인가 코드 발급 성공!");
        System.out.println("📋 Code: " + code);
        System.out.println("============================================");

        return "인가 코드 : " + code;
    }
}
