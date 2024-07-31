package com.satyatmawinarga.todoApp.jwt;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;

import java.time.Instant;

@Data
@Builder
public class RefreshToken {
    @Id
    private String id;
    private String token;

    private Instant expiryDate;
    private String username;
}
