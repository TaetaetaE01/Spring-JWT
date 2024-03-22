package com.example.jwt.global.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String NO_CHECK_URL_LOGIN = "/api/auth";

    private final JwtProvider jwtProvider;

    /**
     * 실제 필터릴 로직
     * 토큰의 인증정보를 SecurityContext에 저장하는 역할 수행
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        /**
         * 로그인 여부를 판단하지 않고 진입할 url
         */
        if (request.getRequestURI().equals(NO_CHECK_URL_LOGIN)) {
            filterChain.doFilter(request, response);
            return; // return으로 이후 현재 필터 진행 막기 (안해주면 아래로 내려가서 계속 필터 진행시킴)
        }

        /**
         * accessToken header에서 추출 후 유효성 검증
         * 아닐시 null 반환
         */
        String jwtToken = jwtProvider.extractAccessToken(request)
                .filter(jwtProvider::validateToken)
                .orElse(null);

        if (jwtToken != null) {
            Authentication authentication = jwtProvider.getAuthentication(jwtToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.info("ACCESS_TOKEN 유저 정보 추출 후 authentication 객체 저장 완료");
            filterChain.doFilter(request, response);
        } else {
            log.info("유효한 JWT 토큰이 없습니다. requestURI : {}", request.getRequestURI());
        }


    }


}