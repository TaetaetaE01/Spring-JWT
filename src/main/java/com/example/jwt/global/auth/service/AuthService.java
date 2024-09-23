package com.example.jwt.global.auth.service;

import com.example.jwt.domain.member.dto.request.MemberLoginRegister;
import com.example.jwt.domain.member.entity.Member;
import com.example.jwt.domain.member.service.MemberService;
import com.example.jwt.global.auth.jwt.dto.TokenDto;
import com.example.jwt.global.auth.jwt.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final MemberService memberService;

    private final PasswordEncoder passwordEncoder;

    @Transactional
    public TokenDto signIn(MemberLoginRegister memberLoginRegister) {
        Member member = memberService.findMemberByEmail(memberLoginRegister.getEmail());

        if (!member.isPasswordValid(passwordEncoder, memberLoginRegister.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다");
        }

        return jwtService.signIn(memberLoginRegister.getEmail(), memberLoginRegister.getPassword());
    }
}
