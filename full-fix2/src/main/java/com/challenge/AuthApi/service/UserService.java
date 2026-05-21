package com.challenge.AuthApi.service;

import com.challenge.AuthApi.dto.UpdateUserRequest;
import com.challenge.AuthApi.dto.UserResponse;
import com.challenge.AuthApi.entity.User;
import com.challenge.AuthApi.exception.UserAlreadyExistsException;
import com.challenge.AuthApi.exception.UserNotFoundException;
import com.challenge.AuthApi.repository.UserRepository;
import com.challenge.AuthApi.security.JwtService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Teste 4 — Nunca retorna o campo senha nas respostas.
 * Teste 5 — Logs de auditoria em todas as ações críticas (sem dados sensíveis).
 */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository  = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private UserResponse toResponse(User u) {
        return new UserResponse(u.getId(), u.getNome(), u.getEmail(), u.getRole());
    }

    // ── CRUD ─────────────────────────────────────────────────────────────────

    public User createUser(User user) {
        userRepository.findByEmail(user.getEmail()).ifPresent(u -> {
            throw new UserAlreadyExistsException("User already exists with this email");
        });

        user.setSenha(passwordEncoder.encode(user.getSenha()));

        if (user.getRole() == null || user.getRole().isBlank()) {
            user.setRole("USER");
        }

        User saved = userRepository.save(user);

        // Teste 5 — auditoria: registro de criação (sem senha)
        log.info("[AUDIT] CRIAR_USUARIO id={} email={} role={}", saved.getId(), saved.getEmail(), saved.getRole());

        return saved;
    }

    public User authenticate(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    // Teste 5 — auditoria: tentativa com e-mail desconhecido (sem logar a senha)
                    log.warn("[AUDIT] LOGIN_FALHOU motivo=usuario_nao_encontrado email={}", email);
                    return new UsernameNotFoundException("User not found");
                });

        if (!passwordEncoder.matches(password, user.getSenha())) {
            // Teste 5 — auditoria: senha incorreta
            log.warn("[AUDIT] LOGIN_FALHOU motivo=senha_incorreta email={}", email);
            throw new BadCredentialsException("Invalid password");
        }

        // Teste 5 — auditoria: login bem-sucedido
        log.info("[AUDIT] LOGIN_OK email={} role={}", user.getEmail(), user.getRole());
        return user;
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /** Teste 4 — Retorna lista sem o campo senha */
    public List<UserResponse> findAllAsResponse() {
        return userRepository.findAll()
                .stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /** Teste 4 + 5 — Update via DTO dedicado + auditoria */
    public UserResponse update(Long id, UpdateUserRequest req) {
        User existing = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (req.nome() != null)  existing.setNome(req.nome());

        if (req.email() != null) {
            userRepository.findByEmail(req.email()).ifPresent(u -> {
                if (!u.getId().equals(id))
                    throw new UserAlreadyExistsException("Email already in use");
            });
            existing.setEmail(req.email());
        }

        if (req.senha() != null && !req.senha().isBlank()) {
            existing.setSenha(passwordEncoder.encode(req.senha()));
        }

        if (req.role() != null) existing.setRole(req.role());

        User saved = userRepository.save(existing);

        // Teste 5 — auditoria: atualização (sem logar a senha nova)
        log.info("[AUDIT] ATUALIZAR_USUARIO id={} email={} role={}", saved.getId(), saved.getEmail(), saved.getRole());

        return toResponse(saved);
    }

    public void delete(Long id) {
        if (!userRepository.existsById(id)) {
            throw new UserNotFoundException("User not found");
        }
        userRepository.deleteById(id);

        // Teste 5 — auditoria: exclusão
        log.info("[AUDIT] DELETAR_USUARIO id={}", id);
    }

    public User validateToken(String token, JwtService jwtService) {
        if (!jwtService.isValid(token)) {
            log.warn("[AUDIT] TOKEN_INVALIDO");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token inválido");
        }

        String email = jwtService.extractEmail(token);

        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuário não encontrado")
                );
    }
}
