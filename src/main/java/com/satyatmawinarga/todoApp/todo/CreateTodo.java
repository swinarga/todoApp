package com.satyatmawinarga.todoApp.todo;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.annotation.Id;

public record CreateTodo(
        @NotNull
        @NotEmpty
        String title,
        String description,
        Boolean done
) {
}
