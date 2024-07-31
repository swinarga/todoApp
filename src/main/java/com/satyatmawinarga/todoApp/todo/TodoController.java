package com.satyatmawinarga.todoApp.todo;

import com.satyatmawinarga.todoApp.user.UserController;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/todos")
public class TodoController {
    private final TodoRepository todoRepository;

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    public TodoController(TodoRepository todoRepository) {
        this.todoRepository = todoRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("")
    public List<Todo> findAll() {
        return todoRepository.findAll();
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/{id}")
    public Todo findById(@PathVariable String id, Principal principal) {
        String currentUsername = principal.getName();

        logger.debug("Current username: {}", currentUsername);
        Todo todo = todoRepository.findById(id)
                .orElseThrow(() -> new TodoNotFoundException(id));

        if (!todo.username().equals(currentUsername)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You do not have " +
                    "access to this resource");
        }
        return todo;
    }

    @PreAuthorize("hasRole('USER')")
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("")
    public void create(@Valid @RequestBody CreateTodo todo, Principal principal) {
        String currentUsername = principal.getName();
        todoRepository.save(new Todo(null, currentUsername, todo.title(),
                todo.description(),
                todo.done()));
    }

    @PreAuthorize("hasRole('USER')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PutMapping("/{id}")
    public void update(@Valid @RequestBody UpdateTodo todo, @PathVariable String id,
                       Principal principal) {
        String currentUsername = principal.getName();

        Todo existingTodo = todoRepository.findById(id)
                .orElseThrow(() -> new TodoNotFoundException(id));

        if (!existingTodo.username().equals(currentUsername)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You do not have " +
                    "access to this resource");
        }

        Todo updatedTodo = applyUpdates(existingTodo, todo);
        todoRepository.save(updatedTodo);
    }

    @PreAuthorize("hasRole('USER')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id, Principal principal) {
        String currentUsername = principal.getName();

        Todo todo = todoRepository.findById(id)
                .orElseThrow(() -> new TodoNotFoundException(id));

        if (!todo.username().equals(currentUsername)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You do not have " +
                    "access to this resource");
        }

        todoRepository.deleteById(id);
    }

    private Todo applyUpdates(Todo existingTodo, UpdateTodo todoUpdateDTO) {
        String title = todoUpdateDTO.title().orElse(existingTodo.title());
        String description =
                todoUpdateDTO.description().orElse(existingTodo.description());
        Boolean completed = todoUpdateDTO.done().orElse(existingTodo.done());

        return new Todo(
                existingTodo.id(),
                existingTodo.username(),
                title,
                description,
                completed
        );
    }
}
