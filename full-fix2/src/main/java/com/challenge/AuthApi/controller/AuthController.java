package com.challenge.AuthApi.controller;

import com.challenge.AuthApi.dto.AuthResponse;
import com.challenge.AuthApi.dto.LoginRequest;
import com.challenge.AuthApi.dto.RegisterRequest;
import com.challenge.AuthApi.dto.UserResponse;
import com.challenge.AuthApi.dto.ValidateTokenRequest;
import com.challenge.AuthApi.dto.ValidateTokenResponse;
import com.challenge.AuthApi.entity.User;
import com.challenge.AuthApi.security.JwtService;
import com.challenge.AuthApi.service.UserService;

import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log =
            LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final JwtService jwtService;

    public AuthController(
            UserService userService,
            JwtService jwtService
    ) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @RequestBody @Valid RegisterRequest request
    ) {

        log.info("[AUDIT] REGISTER tentativa email={}", request.email());

        User user = new User();

        user.setNome(request.nome());
        user.setEmail(request.email());
        user.setSenha(request.senha());

        // proteção extra contra role inválida
        String role = request.role().toUpperCase();

        if (!role.equals("USER") && !role.equals("ADMIN")) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Role inválida"
            );
        }

        user.setRole(role);

        User saved = userService.createUser(user);

        log.info("[AUDIT] REGISTER sucesso email={}", saved.getEmail());

        UserResponse response = new UserResponse(
                saved.getId(),
                saved.getNome(),
                saved.getEmail(),
                saved.getRole()
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody @Valid LoginRequest request
    ) {

        log.info("[AUDIT] LOGIN tentativa email={}", request.email());

        try {

            User user = userService.authenticate(
                    request.email(),
                    request.senha()
            );

            String token = jwtService.generateToken(
                    user.getEmail(),
                    user.getRole()
            );

            log.info("[AUDIT] LOGIN sucesso email={}", user.getEmail());

            return ResponseEntity.ok(
                    new AuthResponse(
                            token,
                            user.getEmail(),
                            user.getRole()
                    )
            );

        } catch (AuthenticationException e) {

            log.warn("[AUDIT] LOGIN falha email={}", request.email());

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Credenciais inválidas");

        } catch (ResponseStatusException e) {

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(e.getReason());
        }
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidateTokenResponse> validateToken(
            @RequestBody @Valid ValidateTokenRequest request
    ) {

        try {

            User user = userService.validateToken(
                    request.token(),
                    jwtService
            );

            log.info(
                    "[AUDIT] VALIDATE_TOKEN sucesso email={}",
                    user.getEmail()
            );

            return ResponseEntity.ok(
                    new ValidateTokenResponse(
                            true,
                            user.getEmail(),
                            user.getRole()
                    )
            );

        } catch (ResponseStatusException e) {

            log.warn("[AUDIT] VALIDATE_TOKEN token inválido");

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(
                            new ValidateTokenResponse(
                                    false,
                                    null,
                                    null
                            )
                    );
        }
    }
}