package com.satyatmawinarga.todoApp.todo;

import java.util.Optional;

public record UpdateTodo(
        Optional<String> title,
        Optional<String> description,
        Optional<Boolean> done
) {
}
