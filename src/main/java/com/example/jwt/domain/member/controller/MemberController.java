package com.example.jwt.domain.member.controller;

import com.example.jwt.domain.member.dto.request.MemberLoginRegister;
import com.example.jwt.domain.member.dto.request.MemberRegisterRequest;
import com.example.jwt.domain.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/jwt/member")
public class MemberController {

    private final MemberService memberService;

    @PostMapping
    public ResponseEntity<String> register(@RequestBody MemberRegisterRequest memberRegisterRequest) {
        memberService.registerMember(memberRegisterRequest);
        return ResponseEntity.ok().body("성공적으로 회원등록이 완료되었습니다.");
    }
}
