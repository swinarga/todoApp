package com.satyatmawinarga.todoApp.jwt;

public record RefreshTokenResponse(
        String accessToken,
        String refreshToken
) {
}
