package com.satyatmawinarga.todoApp.todo;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/todos")
public class TodoController {

    private final TodoRepository todoRepository;

    public TodoController(TodoRepository todoRepository) {
        this.todoRepository = todoRepository;
    }

    @GetMapping("")
    public List<Todo> findAll() {
        return todoRepository.findAll();
    }

    @GetMapping("/{id}")
    public Todo findById(@PathVariable String id) {
        return todoRepository.findById(id)
                .orElseThrow(() -> new TodoNotFoundException(id));
    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("")
    public void create(@Valid @RequestBody CreateTodo todo) {
        todoRepository.save(new Todo(null, todo.title(), todo.description(),
                todo.done()));
    }

    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PutMapping("/{id}")
    public void update(@Valid @RequestBody UpdateTodo todo, @PathVariable String id) {
        Optional<Todo> existingTodo = todoRepository.findById(id);

        if (existingTodo.isEmpty()) {
            throw new TodoNotFoundException(id);
        }
        Todo updatedTodo = applyUpdates(existingTodo.get(), todo);
        todoRepository.save(updatedTodo);
    }

    @ResponseStatus(HttpStatus.NO_CONTENT)
    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        todoRepository.deleteById(id);
    }

    private Todo applyUpdates(Todo existingTodo, UpdateTodo todoUpdateDTO) {
        String title = todoUpdateDTO.title().orElse(existingTodo.title());
        String description =
                todoUpdateDTO.description().orElse(existingTodo.description());
        Boolean completed = todoUpdateDTO.done().orElse(existingTodo.done());

        return new Todo(
                existingTodo.id(),
                title,
                description,
                completed
        );
    }
}
