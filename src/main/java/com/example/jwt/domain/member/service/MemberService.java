package com.example.jwt.domain.member.service;

import com.example.jwt.domain.member.dto.request.MemberRegisterRequest;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@NoArgsConstructor
public class MemberService {
    @Transactional
    public void registerMember(MemberRegisterRequest memberRegisterRequest) {
    }
}
