package com.satyatmawinarga.todoApp.jwt;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record RefreshTokenRequest(
        @NotEmpty
        @NotNull
        String refreshToken
) {
}
