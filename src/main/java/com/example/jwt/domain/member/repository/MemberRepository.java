package com.example.jwt.domain.member.repository;

import com.example.jwt.domain.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.swing.plaf.metal.MetalMenuBarUI;
import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email);
}
