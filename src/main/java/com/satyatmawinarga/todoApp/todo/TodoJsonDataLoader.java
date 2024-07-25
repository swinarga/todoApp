package com.satyatmawinarga.todoApp.todo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;

@Component
public class TodoJsonDataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(TodoJsonDataLoader.class);
    private final TodoRepository repository;
    private final ObjectMapper objectMapper;

    public TodoJsonDataLoader(TodoRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;

        // we need ObjectMapper to deserialize JSON data
        // into Java objects
        this.objectMapper = objectMapper;
    }

    @Override
    public void run(String... args) throws Exception {
        if (repository.count() == 0) {
            try (InputStream inputStream =
                         TypeReference.class.getResourceAsStream("/data/todos.json")) {
                Todos allTodos = objectMapper.readValue(inputStream, Todos.class);
                // deserialize JSON data into Todos object
                log.info("Reading {} Todos from JSON data " +
                                "and saving to database" +
                                "collection.",
                        allTodos.todos().size());
                repository.saveAll(allTodos.todos());

                // fetch all customers
                System.out.println("Todos found with findAll():");
                System.out.println("-------------------------------");
                for (Todo todo : repository.findAll()) {
                    System.out.println(todo);
                }
                System.out.println();
            } catch (IOException e) {
                throw new RuntimeException("Failed to " +
                        "read JSON data", e);
            }
        } else {
            log.info("Not loading Todos from JSON data " +
                    "because the collection contains data" +
                    ".");
        }
    }
}
