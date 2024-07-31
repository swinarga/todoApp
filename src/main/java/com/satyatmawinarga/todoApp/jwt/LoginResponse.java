package com.satyatmawinarga.todoApp.jwt;

import java.util.List;

public record LoginResponse(
        String username,
        List<String> roles,
        String jwtToken,
        String refreshToken
) {
}
