package com.gearfirst.backend.api.auth.controller;


import com.gearfirst.backend.api.auth.service.AuthService;
import com.gearfirst.backend.api.auth.service.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class AuthController {
    @GetMapping("/login")
    public String loginForm() {
        System.out.println(" AuthController.loginForm() 호출됨!");
        return "login"; // templates/login.html
    }
}
