package com.satyatmawinarga.todoApp.todo;

import jakarta.validation.constraints.NotEmpty;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;

public record Todo(
        @Id
        String id,
        @Indexed
        String username,
        @NotEmpty
        String title,
        String description,
        Boolean done
) {
}
