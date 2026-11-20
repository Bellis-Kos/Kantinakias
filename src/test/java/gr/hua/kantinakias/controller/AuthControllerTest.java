package gr.hua.kantinakias.controller;

import gr.hua.kantinakias.dto.auth.LoginRequest;
import gr.hua.kantinakias.dto.auth.RegisterRequest;
import gr.hua.kantinakias.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthControllerTest {

    @Test
    void registrationReturnsCreatedWithJwt() throws Exception {
        AuthService authService = mock(AuthService.class);
        when(authService.register(any(RegisterRequest.class))).thenReturn("jwt-token");
        MockMvc mockMvc = createMockMvc(authService);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"new@example.com","password":"secret-password"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").value("jwt-token"));
    }

    @Test
    void loginReturnsJwtAndInvalidCredentialsReturnUnauthorized() throws Exception {
        AuthService authService = mock(AuthService.class);
        when(authService.login(any(LoginRequest.class))).thenReturn("jwt-token");
        when(authService.login(org.mockito.ArgumentMatchers.argThat(
                request -> request.email().equals("bad@example.com"))))
                .thenThrow(new BadCredentialsException("Bad credentials."));
        MockMvc mockMvc = createMockMvc(authService);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"good@example.com","password":"secret-password"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"bad@example.com","password":"wrong-password"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password."));
    }

    @Test
    void duplicateRegistrationReturnsConflict() throws Exception {
        AuthService authService = mock(AuthService.class);
        when(authService.register(any(RegisterRequest.class)))
                .thenThrow(new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.CONFLICT,
                        "Email is already registered."));
        MockMvc mockMvc = createMockMvc(authService);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"existing@example.com","password":"secret-password"}
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email is already registered."));
    }

    private static MockMvc createMockMvc(AuthService authService) {
        return MockMvcBuilders.standaloneSetup(new AuthController(authService))
                .setControllerAdvice(new AuthExceptionHandler())
                .build();
    }
}
