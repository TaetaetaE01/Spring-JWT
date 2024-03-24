package com.example.jwt.domain.member.dto.request;

import lombok.Getter;

@Getter
public class MemberLoginRegister {
    private String email;
    private String password;
}
