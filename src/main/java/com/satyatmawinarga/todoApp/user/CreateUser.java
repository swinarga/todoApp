package com.satyatmawinarga.todoApp.user;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record CreateUser(
        @NotEmpty
        @NotNull
        String username,
        @NotEmpty
        @NotNull
        String password) {
}
