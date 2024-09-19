package com.example.jwt.global.auth.service;

import com.example.jwt.domain.member.dto.request.MemberLoginRegister;
import com.example.jwt.global.auth.jwt.dto.TokenDto;
import com.example.jwt.global.auth.jwt.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;


    @Transactional
    public String signIn(MemberLoginRegister memberLoginRegister) {
        jwtService.signIn(memberLoginRegister.getEmail(), memberLoginRegister.getPassword());

        TokenDto tokenDto = jwtService.createAllToken(member);
        return tokenDto.getAccessToken();
    }
}
