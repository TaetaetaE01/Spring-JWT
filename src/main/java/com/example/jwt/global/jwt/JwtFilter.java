package com.example.jwt.global.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String NO_CHECK_URL_LOGIN = "/api/auth";


    private final JwtService jwtService;

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

//        String accessToken = jwtService.resolveToken(request);

        /**
         * accessToken header에서 추출 후 유효성 검증
         * 아닐시 null 반환
         */
        String accessToken = jwtService.extractAccessToken(request)
                .filter(jwtService::validateToken)
                .orElse(null);

        if (StringUtils.hasText(accessToken)) {
            Authentication authentication = jwtService.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.info("ACCESS_TOKEN 유저 정보 추출 후 authentication 객체 저장 완료");
            filterChain.doFilter(request, response);
        }


        if (StringUtils.hasText(accessToken)) {
            Authentication authentication = jwtService.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } else if (accessToken != null && !jwtService.validateToken(accessToken)) {
            // 액세스 토큰이 만료되었을 때
            String email = jwtService.getMemberEmailFromToken(accessToken);
            Optional<RefreshToken> refreshToken = jwtService.findByEmail(email);

            if (refreshToken.isPresent() && jwtService.validateToken(
                    refreshToken.get().getRefreshToken())) {
                // 리프레시 토큰이 유효한 경우
                String newAccessToken = jwtService.createAccessToken(email);
                if (newAccessToken != null) {
                    // 새로운 액세스 토큰을 생성하고 클라이언트에게 전달
                    response.setHeader("New-Access-Token", newAccessToken);
                }
            }
        }

        filterChain.doFilter(request, response);
    }


}