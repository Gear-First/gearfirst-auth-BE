package com.gearfirst.backend.api.auth.controller;



import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class AuthController {
    @GetMapping("/login")
    public String loginForm(@RequestParam(required = false) String error, Model model) {
        if (error != null) {
            model.addAttribute("errorMessage", "이메일 또는 비밀번호가 올바르지 않습니다.");
        }
        return "login"; // templates/login.html
    }
}
