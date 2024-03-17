package com.example.jwt.domain.member.dto.request;

import lombok.Getter;

@Getter
public class MemberRegisterRequest {
    private String email;
    private String password;
    private String name;
}
