package gr.hua.kantinakias.controller;

import gr.hua.kantinakias.dto.auth.AuthResponse;
import gr.hua.kantinakias.dto.auth.LoginRequest;
import gr.hua.kantinakias.dto.auth.RegisterRequest;
import gr.hua.kantinakias.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new AuthResponse(authService.register(request)));
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest request) {
        return new AuthResponse(authService.login(request));
    }
}
