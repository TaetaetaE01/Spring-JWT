package com.example.jwt.global.auth.jwt.service;


import com.example.jwt.global.auth.jwt.dto.RefreshToken;
import com.example.jwt.global.auth.jwt.dto.TokenDto;
import com.example.jwt.global.auth.jwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.util.*;


@Component
@Slf4j
@RequiredArgsConstructor
public class JwtProvider {
    @Value("${jwt.secret-key}")
    private String secretKey;

    private static final String ACCESS_TOKEN_HEADER = "AUTH-KEY";
    private static final String BEARER = "BEARER";


    private final UserDetailsService userDetailsService;
    private final RefreshTokenRepository refreshTokenRepository;

    private static final long ACCESS_TIME = 10 * 60 * 1000L; // 10분
    private static final long REFRESH_TIME = 20 * 60 * 1000L;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // 토큰 생성 order -> dto에 바로 담음
    public TokenDto createAllToken(String email, String role) {
        return new TokenDto(createToken(email, role, "Access"), createToken(email, role, "Refresh"));
    }

    // 토큰 생성 (access, refresh)
    public String createToken(String email, String role, String type) {
        Claims claims = Jwts.claims().setSubject(email);
        claims.put("role", role);

        long expiration = type.equals("Access") ? ACCESS_TIME : REFRESH_TIME;

        Date now = new Date();
        long nowTime = now.getTime();
        Date validity = new Date(nowTime + expiration);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    // 헤더에 있는 access 토큰 추출
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(ACCESS_TOKEN_HEADER))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUserPk(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    // 토큰 유효성(시간 만료) 검증
    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String getMemberEmailFromToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return claims.getBody().getSubject();
        } catch (Exception e) {
            log.error("Failed to extract username from token", e);
            return null;
        }
    }

    public Optional<RefreshToken> findByEmail(String email) {
        return refreshTokenRepository.findByEmail(email);
    }

}
