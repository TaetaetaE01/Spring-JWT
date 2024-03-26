package com.example.jwt.global.auth.jwt.repository;

import com.example.jwt.global.auth.jwt.dto.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByEmail(String email);

}
