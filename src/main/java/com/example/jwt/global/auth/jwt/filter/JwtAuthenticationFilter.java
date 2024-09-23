package com.example.jwt.global.auth.jwt.filter;

import com.example.jwt.global.auth.jwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String NO_CHECK_URL_LOGIN = "/api/jwt/auth/login";
    public static final String NO_CHECK_URL_SIGN_UP = "/api/jwt/member";

    private final JwtService jwtService;

    /**
     * 실제 필터릴 로직
     * 토큰의 인증정보를 SecurityContext에 저장하는 역할 수행
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        /**
         * 로그인 여부를 판단하지 않고 진입할 url
         * 회원가입 && LOGIN
         */
        if (request.getRequestURI().equals(NO_CHECK_URL_LOGIN) || request.getRequestURI().equals(NO_CHECK_URL_SIGN_UP)) {
            filterChain.doFilter(request, response);
            return; // return으로 이후 현재 필터 진행 막기 (안해주면 아래로 내려가서 계속 필터 진행시킴)
        }

        /**
         * accessToken header에서 추출 후 유효성 검증
         * 아닐시 null 반환
         */
        String accessToken = jwtService.extractAccessToken(request)
                .filter(jwtService::validateToken)
                .orElse(null);

        if (accessToken != null) {
            // Access Token이 유효할 경우 인증 객체 저장
            Authentication authentication = jwtService.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("ACCESS_TOKEN 유효성 확인 후 SecurityContext에 인증 정보 저장 완료");
        } else {
            // Refresh Token 검증
            String refreshToken = jwtService.extractRefreshToken(request)
                    .filter(jwtService::validateToken)
                    .orElse(null);

            if (refreshToken != null) {
                // Refresh Token이 유효할 경우 Access Token 재발급 및 인증 객체 저장
                Authentication authentication = jwtService.getAuthentication(refreshToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("REFRESH_TOKEN 유효성 확인 후 SecurityContext에 인증 정보 저장 완료");
            } else {
                // 예외 처리
                log.info("유효한 JWT 토큰이 없습니다. requestURI : {}", request.getRequestURI());
            }
        }
    }
}