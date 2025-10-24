package com.gearfirst.backend.api.infra.client;

import com.gearfirst.backend.api.infra.dto.UserLoginRequest;
import com.gearfirst.backend.api.infra.dto.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", url = "http://user-service:8081") // MSA 환경이라면 Eureka, Consul 등 사용 가능
public interface UserClient {

    @PostMapping("/api/v1/users/verify")
    UserResponse verifyUser(@RequestBody UserLoginRequest request);
}
