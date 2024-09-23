package com.example.jwt.global.auth.controller;

import com.example.jwt.domain.member.dto.request.MemberLoginRegister;
import com.example.jwt.domain.member.dto.request.MemberRegisterRequest;
import com.example.jwt.domain.member.service.MemberService;
import com.example.jwt.global.auth.jwt.dto.TokenDto;
import com.example.jwt.global.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/jwt/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping()
    public ResponseEntity<String> register(@RequestBody MemberRegisterRequest memberRegisterRequest) {
        authService.registerMember(memberRegisterRequest);
        return ResponseEntity.ok().body("성공적으로 회원등록이 완료되었습니다.");
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody MemberLoginRegister memberLoginRegister) {
        return ResponseEntity.ok().body(authService.login(memberLoginRegister));
    }
}
