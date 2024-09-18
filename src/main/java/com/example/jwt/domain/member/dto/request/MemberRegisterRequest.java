package com.example.jwt.domain.member.dto.request;

import com.example.jwt.domain.member.entity.Member;
import com.example.jwt.domain.member.entity.auth.Role;
import lombok.Getter;

@Getter
public class MemberRegisterRequest {
    private String email;
    private String password;
    private String name;

    public Member toMemberEntity() {
        return Member.builder()
                .email(email)
                .password(password)
                .name(name)
                .role(Role.USER)
                .build();
    }
}
