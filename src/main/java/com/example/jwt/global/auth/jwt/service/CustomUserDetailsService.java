package com.example.jwt.global.auth.jwt.service;

import com.example.jwt.domain.member.entity.Member;
import com.example.jwt.domain.member.repository.MemberRepository;
import com.example.jwt.global.auth.jwt.dto.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("해당하는 회원정보를 찾을 수 없습니다"));
        return new CustomUserDetails(member);
    }
}
