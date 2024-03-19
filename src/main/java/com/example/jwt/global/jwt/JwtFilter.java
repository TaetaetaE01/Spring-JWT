package com.example.jwt.global.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.logging.Logger;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = tokenProvider.resolveToken(request);

        if (token != null && tokenProvider.validateToken(token)) {
            Authentication authentication = tokenProvider.getAuthentication(token);

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else if (token != null && !tokenProvider.validateToken(token)) {
            // 액세스 토큰이 만료되었을 때
            String email = tokenProvider.getMemberEmailFromToken(token);
            Optional<RefreshToken> refreshToken = tokenProvider.findByEmail(email);
            if (refreshToken.isPresent() && tokenProvider.validateToken(
                    refreshToken.get().getRefreshToken())) {
                // 리프레시 토큰이 유효한 경우
                String newAccessToken = tokenProvider.createAccessToken(email);
                if (newAccessToken != null) {
                    // 새로운 액세스 토큰을 생성하고 클라이언트에게 전달
                    response.setHeader("New-Access-Token", newAccessToken);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}