package com.satyatmawinarga.todoApp.user;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;

import java.util.List;

@Data
@Builder
public class User {
    @Id
    private String id;
    @Indexed
    private String username;
    private String password;
    private List<String> roles; // e.g. USER, ADMIN
}
