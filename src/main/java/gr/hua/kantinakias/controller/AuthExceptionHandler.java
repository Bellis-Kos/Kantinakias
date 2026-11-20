package gr.hua.kantinakias.controller;

import gr.hua.kantinakias.dto.auth.AuthErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<AuthErrorResponse> handleAuthenticationFailure(
            AuthenticationException exception) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new AuthErrorResponse("Invalid email or password."));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<AuthErrorResponse> handleInvalidRequest(IllegalArgumentException exception) {
        return ResponseEntity.badRequest()
                .body(new AuthErrorResponse(exception.getMessage()));
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<AuthErrorResponse> handleRequestFailure(ResponseStatusException exception) {
        return ResponseEntity.status(exception.getStatusCode())
                .body(new AuthErrorResponse(exception.getReason()));
    }
}
