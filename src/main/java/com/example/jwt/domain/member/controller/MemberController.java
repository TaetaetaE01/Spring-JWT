package com.example.jwt.domain.member.controller;


import com.example.jwt.domain.member.entity.Member;
import com.example.jwt.domain.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/jwt/member")
public class MemberController {

    private final MemberService memberService;

    @GetMapping("/{memberId}")
    public ResponseEntity<Member> getMemberInfo(@PathVariable("memberId") Long memberId) {
        log.info(String.valueOf(memberId));
        Member member = memberService.findByMemberId(memberId);
        return ResponseEntity.ok().body(member);
    }

    @GetMapping()
    public ResponseEntity<List<Member>> getMembers() {
        return null;
    }

}
