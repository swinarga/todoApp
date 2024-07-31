package com.satyatmawinarga.todoApp.jwt;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * unauthorized may be preferable
 * as opposed to not found to avoid
 * providing hints to potential attackers
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class RefreshTokenNotFoundException extends RuntimeException {
    public RefreshTokenNotFoundException() {
        super("Unauthorized");
    }
}
