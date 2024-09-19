package com.example.jwt.global.auth.controller;

import com.example.jwt.domain.member.dto.request.MemberLoginRegister;
import com.example.jwt.domain.member.entity.Member;
import com.example.jwt.domain.member.repository.MemberRepository;
import com.example.jwt.global.auth.jwt.dto.TokenDto;
import com.example.jwt.global.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody MemberLoginRegister memberLoginRegister) {
        authService.signIn(memberLoginRegister);
        return ResponseEntity.ok().body("토큰임둥~~~");
    }
}
