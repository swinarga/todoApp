package com.satyatmawinarga.todoApp.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class RefreshTokenService {
    @Autowired
    RefreshTokenRepository refreshTokenRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            System.out.println("Refresh token expired");
            throw new RefreshTokenExpiredException();
        }
        return token;
    }

    public RefreshToken validateRefreshToken(String refreshToken) throws RefreshTokenNotFoundException {
        return refreshTokenRepository.findByToken(refreshToken)
                .map(this::verifyExpiration)
                .orElseThrow(RefreshTokenNotFoundException::new);
    }
}
