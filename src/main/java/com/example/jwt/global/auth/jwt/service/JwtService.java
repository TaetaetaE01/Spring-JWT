package com.example.jwt.global.auth.jwt.service;


import com.example.jwt.global.auth.jwt.dto.TokenDto;
import com.example.jwt.global.auth.jwt.entity.RefreshToken;
import com.example.jwt.global.auth.jwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@Component
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.secret-key}")
    private String secretKey;

    private Key key;

    private static final String ACCESS_TOKEN_HEADER = "ACCESS-AUTH-KEY";
    private static final String REFRESH_TOKEN_HEADER = "REFRESH-AUTH-KEY";
    private static final String BEARER = "BEARER";
    private static final String ACCESS_TOKEN_TYPE = "Access";
    private static final String REFRESH_TOKEN_TYPE = "Refresh";

    private final UserDetailsService userDetailsService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private static final long ACCESS_TIME = 10 * 60 * 1000L; // 10분
    private static final long REFRESH_TIME = 20 * 60 * 1000L;

    @PostConstruct
    protected void init() {
        key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public TokenDto signIn(String email, String password) {
        // principal (사용자명), credentials (비밀번호)
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);

        // 2. 실제 검증 (사용자 비밀번호 체크)
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        TokenDto tokenDto = createAllToken(authentication);
        saveRefreshTokenToRedis(authentication.getName(), tokenDto.getRefreshToken());

        return tokenDto;
    }

    // 토큰 생성 order -> dto에 바로 담음
    public TokenDto createAllToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return new TokenDto(createToken(authentication.getName(), authorities, ACCESS_TOKEN_TYPE),
                createToken(authentication.getName(), authorities, REFRESH_TOKEN_TYPE));
    }

    // 헤더에 있는 access 토큰 추출
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(ACCESS_TOKEN_HEADER))
                .filter(accessToken -> accessToken.startsWith(BEARER))
                .map(accessToken -> accessToken.replace(BEARER, ""));
    }

    // 헤더에 있는 refresh 토큰 추출
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(REFRESH_TOKEN_HEADER))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUserPk(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(jwtToken);
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

    // 토큰 생성 (access, refresh)
    private String createToken(String email, String authorities, String type) {
        long expiration = type.equals("Access") ? ACCESS_TIME : REFRESH_TIME;

        Date now = new Date();
        long nowTime = now.getTime();
        Date validity = new Date(nowTime + expiration);

        return Jwts.builder()
                .setSubject(email)
                .claim("role", authorities)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    private void saveRefreshTokenToRedis(String email, String refreshToken) {
        RefreshToken refreshTokenEntity = new RefreshToken(email, refreshToken);
        refreshTokenRepository.save(refreshTokenEntity);
    }
}
