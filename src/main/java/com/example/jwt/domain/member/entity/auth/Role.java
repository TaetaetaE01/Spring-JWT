package com.example.jwt.domain.member.entity.auth;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.List;

@Getter
@RequiredArgsConstructor
public enum Role {
    USER("ROLE_USER"),
    ADMIN("ROLE_ADMIN");

    private final String roles;

    public List<String> getRoles() {
        return Arrays.asList(roles.split(","));
    }
}
