package com.gearfirst.backend.api.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RequiredArgsConstructor
public class OAuthCallbackController {
//    private final RestClient restClient = RestClient.create("https://auth.example.com");
//
//    @PostMapping("/exchange")
//    public Map<String, Object> exchangeToken(@RequestBody Map<String, String> body) {
//        String code = body.get("code");
//        String codeVerifier = body.get("code_verifier");
//
//        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
//        form.add("grant_type", "authorization_code");
//        form.add("client_id", "gearfirst-client");
//        form.add("code", code);
//        form.add("redirect_uri", "https://api.example.com/auth/callback");
//        form.add("code_verifier", codeVerifier);
//
//        return restClient.post()
//                .uri("/oauth2/token")
//                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
//                .body(form)
//                .retrieve()
//                .body(new ParameterizedTypeReference<>() {});
//    }
}
