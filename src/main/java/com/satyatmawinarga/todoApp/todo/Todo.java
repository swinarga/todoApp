package com.satyatmawinarga.todoApp.todo;

import jakarta.validation.constraints.NotEmpty;
import org.springframework.data.annotation.Id;

public record Todo(
        @Id
        String id,
        @NotEmpty
        String title,
        String description,
        Boolean done
) {
}
