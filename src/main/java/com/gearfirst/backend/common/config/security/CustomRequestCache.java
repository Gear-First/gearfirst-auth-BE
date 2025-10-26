package com.gearfirst.backend.common.config.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * CustomRequestCache
 *  - 사용자가 인증 후 원래 요청한 URL로 리다이렉트할 때 사용되는 SavedRequest를 세션에 저장/복원
 *  - 저장 및 복원 시점에 디버그 로그 출력
 */
public class CustomRequestCache extends HttpSessionRequestCache {

    @Override
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
        System.out.println(" [CustomRequestCache] 요청 저장 시도: " + uri);

        //  /error는 저장하지 않음
        if (uri.startsWith("/error")) {
            System.out.println(" [CustomRequestCache] /error 요청은 저장하지 않음");
            return;
        }

        //  그 외의 요청만 저장
        super.saveRequest(request, response);
        System.out.println(" [CustomRequestCache] SavedRequest 저장 완료: " + uri);

        String query = request.getQueryString();
        System.out.println("    ➤ URI   : " + uri);
        System.out.println("    ➤ Query : " + query);
        System.out.println("    ➤ Full  : " + uri + (query != null ? "?" + query : ""));
    }

    @Override
    public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest savedRequest = super.getRequest(request, response);
        if (savedRequest != null) {
            System.out.println(" [CustomRequestCache] 복원된 SavedRequest:");
            System.out.println("    ➤ Redirect URL : " + savedRequest.getRedirectUrl());
        } else {
            System.out.println(" [CustomRequestCache] 복원된 SavedRequest 없음!");
        }
        return savedRequest;
    }
}
