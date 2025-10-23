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
            return " 로그인 실패 : " + error + "<br>" + desc;
        }
        return "인가 코드 : " + code;
    }
}
