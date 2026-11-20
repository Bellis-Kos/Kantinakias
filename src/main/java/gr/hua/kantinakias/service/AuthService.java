package gr.hua.kantinakias.service;

import gr.hua.kantinakias.dto.auth.LoginRequest;
import gr.hua.kantinakias.dto.auth.RegisterRequest;
import gr.hua.kantinakias.entity.Role;
import gr.hua.kantinakias.entity.User;
import gr.hua.kantinakias.repository.UserRepository;
import gr.hua.kantinakias.security.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    public String register(RegisterRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        requireCredentials(request.email(), request.password());
        if (userRepository.existsByEmail(request.email())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered.");
        }

        User user = userRepository.save(new User(
                request.email(),
                passwordEncoder.encode(request.password()),
                Role.CUSTOMER));
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());
        return jwtUtils.generateJwtToken(authentication);
    }

    public String login(LoginRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        requireCredentials(request.email(), request.password());
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        request.email(), request.password()));
        return jwtUtils.generateJwtToken(authentication);
    }

    private static void requireCredentials(String email, String password) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email must not be blank.");
        }
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("Password must not be blank.");
        }
    }
}
