package com.example.jwt.domain.member.dto.request;

import com.example.jwt.domain.member.entity.Member;
import com.example.jwt.domain.member.entity.auth.Authority;
import lombok.Getter;

@Getter
public class MemberRegisterRequest {
    private String email;
    private String password;
    private String name;

    public Member toEntity() {
        return Member.builder()
                .email(email)
                .password(password)
                .name(name)
                .authority(Authority.USER)
                .build();
    }
}
