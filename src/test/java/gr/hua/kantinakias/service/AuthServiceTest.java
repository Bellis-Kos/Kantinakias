package gr.hua.kantinakias.service;

import gr.hua.kantinakias.dto.auth.LoginRequest;
import gr.hua.kantinakias.dto.auth.RegisterRequest;
import gr.hua.kantinakias.entity.Role;
import gr.hua.kantinakias.entity.User;
import gr.hua.kantinakias.repository.UserRepository;
import gr.hua.kantinakias.security.JwtUtils;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final String TEST_SECRET = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    @Test
    void registersCustomerWithBcryptHashAndReturnsEmailSubjectToken() {
        UserRepository userRepository = mock(UserRepository.class);
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        JwtUtils jwtUtils = new JwtUtils(TEST_SECRET, 60_000);
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        AuthService authService = new AuthService(
                userRepository, passwordEncoder, authenticationManager, jwtUtils);

        String token = authService.register(new RegisterRequest("new@example.com", "secret-password"));
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();

        assertTrue(passwordEncoder.matches("secret-password", savedUser.getPassword()));
        assertEquals(Role.CUSTOMER, savedUser.getRole());
        assertEquals("new@example.com", jwtUtils.getUserNameFromJwtToken(token));
    }

    @Test
    void loginAuthenticatesEmailAndPasswordBeforeReturningToken() {
        UserRepository userRepository = mock(UserRepository.class);
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        JwtUtils jwtUtils = new JwtUtils(TEST_SECRET, 60_000);
        User user = new User(
                "owner@example.com",
                passwordEncoder.encode("secret-password"),
                Role.OWNER);
        Authentication authenticated = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(authenticated);
        AuthService authService = new AuthService(
                userRepository, passwordEncoder, authenticationManager, jwtUtils);

        String token = authService.login(new LoginRequest("owner@example.com", "secret-password"));

        assertEquals("owner@example.com", jwtUtils.getUserNameFromJwtToken(token));
        ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
        verify(authenticationManager).authenticate(authenticationCaptor.capture());
        assertEquals("owner@example.com", authenticationCaptor.getValue().getName());
        assertEquals("secret-password", authenticationCaptor.getValue().getCredentials());
    }
}
