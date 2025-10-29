package com.gearfirst.backend.common.config.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

public class OAuth2DebugFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String uri = request.getRequestURI();

        if (uri.startsWith("/oauth2/authorize")) {
            System.out.println("\n============================");
            System.out.println(" [OAuth2DebugFilter] /oauth2/authorize 요청 감지됨");
            System.out.println(" Method: " + request.getMethod());
            System.out.println(" Full URL: " + request.getRequestURL() +
                    (request.getQueryString() != null ? "?" + request.getQueryString() : ""));

            System.out.println("➡ 파라미터 목록:");
            for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
                System.out.println("   " + entry.getKey() + " = " + String.join(", ", entry.getValue()));
            }
            System.out.println("============================\n");
        }
        if ("/oauth2/token".equals(request.getRequestURI())) {
            request.getParameterMap().forEach((k, v) ->
                    System.out.println("TOKREQ " + k + "=" + String.join(",", v))
            );
        }
//        try {
//            filterChain.doFilter(request, response);
//        } catch (OAuth2AuthorizationCodeRequestAuthenticationException ex) {
//            System.out.println("\n======================");
//            System.out.println(" 🚨 [OAuth2 ERROR DETECTED]");
//            System.out.println(" Request URI: " + uri);
//            System.out.println(" Error Code: " + ex.getError().getErrorCode());
//            System.out.println(" Description: " + ex.getError().getDescription());
//            System.out.println(" Client ID: " + request.getParameter("client_id"));
//            System.out.println(" Redirect URI: " + request.getParameter("redirect_uri"));
//            System.out.println("======================\n");
//            throw ex; // 다시 던져서 Spring이 기본 처리(/error redirect) 수행하도록
//        }

        filterChain.doFilter(request, response);
    }
}
