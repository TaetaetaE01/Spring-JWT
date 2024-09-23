package com.example.jwt.global.auth.jwt.repository;

import com.example.jwt.global.auth.jwt.entity.RefreshToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
}
