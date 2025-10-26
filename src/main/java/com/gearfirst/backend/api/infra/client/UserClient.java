package com.gearfirst.backend.api.infra.client;

import com.gearfirst.backend.api.infra.dto.UserLoginRequest;
import com.gearfirst.backend.api.infra.dto.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", url = "http://localhost:8085")
public interface UserClient {
    @PostMapping("/api/v1/users/verify")
    UserResponse verifyUser(@RequestBody UserLoginRequest request);
}
