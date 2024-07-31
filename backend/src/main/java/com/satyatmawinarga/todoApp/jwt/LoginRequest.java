package com.satyatmawinarga.todoApp.jwt;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record LoginRequest(
        @NotEmpty
        @NotNull
        String username,

        @NotEmpty
        @NotNull
        String password
) {
}
