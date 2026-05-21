package com.challenge.AuthApi.dto;

import jakarta.validation.constraints.*;

/**
 * Teste 4 — DTO específico para atualização.
 * Impede que o cliente envie/altere campos internos como id.
 */
public record UpdateUserRequest(

        @Size(min = 3, max = 100, message = "Nome deve ter entre 3 e 100 caracteres")
        String nome,

        @Email(message = "E-mail inválido")
        @Size(max = 150, message = "E-mail deve ter no máximo 150 caracteres")
        String email,

        @Size(min = 6, max = 72, message = "Senha deve ter entre 6 e 72 caracteres")
        String senha,

        @Pattern(regexp = "^(ADMIN|USER)$", message = "Role deve ser ADMIN ou USER")
        String role
) {}
