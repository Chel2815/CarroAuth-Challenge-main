package com.challenge.AuthApi.dto;

import jakarta.validation.constraints.*;

public record RegisterRequest(

        @NotBlank(message = "Nome é obrigatório")
        @Size(min = 3, max = 50, message = "Nome deve ter entre 3 e 50 caracteres")
        String nome,

        @Email(message = "E-mail inválido")
        @NotBlank(message = "E-mail é obrigatório")
        @Size(max = 150, message = "E-mail deve ter no máximo 150 caracteres")
        String email,

        @NotBlank(message = "Senha é obrigatória")
        @Size(min = 6, max = 72, message = "Senha deve ter entre 6 e 72 caracteres")
        String senha,

        @NotBlank(message = "Role é obrigatória")
        @Pattern(regexp = "^(ADMIN|USER)$", message = "Role deve ser ADMIN ou USER")
        String role
) {}
