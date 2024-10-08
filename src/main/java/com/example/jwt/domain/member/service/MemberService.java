package com.example.jwt.domain.member.service;

import com.example.jwt.domain.member.dto.request.MemberLoginRegister;
import com.example.jwt.domain.member.dto.request.MemberRegisterRequest;
import com.example.jwt.domain.member.entity.Member;
import com.example.jwt.domain.member.repository.MemberRepository;
import com.example.jwt.global.auth.jwt.service.JwtService;
import com.example.jwt.global.auth.jwt.dto.TokenDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    public Member findByMemberId(Long memberId) {
        return memberRepository.findById(memberId)
                .orElseThrow(() -> new IllegalArgumentException("해당하는 회원 정보가 없습니다."));
    }

    @Transactional(readOnly = true)
    public Member findMemberByEmail(String email) {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("해당하는 이메일 정보가 없습니다."));
    }
}
