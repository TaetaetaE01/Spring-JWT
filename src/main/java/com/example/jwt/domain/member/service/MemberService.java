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

    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;

    @Transactional
    public void registerMember(MemberRegisterRequest memberRegisterRequest) {
        Member member = memberRepository.save(memberRegisterRequest.toMemberEntity());
        member.passwordEncode(passwordEncoder);
    }

    @Transactional
    public String login(MemberLoginRegister memberLoginRegister) {
        Member member = findMemberByEmail(memberLoginRegister.getEmail());

        if (!member.isPasswordValid(passwordEncoder, memberLoginRegister.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다");
        }

        TokenDto tokenDto = jwtService.createAllToken(member);
        return tokenDto.getAccessToken();
    }

    @Transactional(readOnly = true)
    public Member findMemberByEmail(String email) {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("해당하는 이메일 정보가 없습니다."));
    }
}
