package com.challenge.AuthApi.dto;

import jakarta.validation.constraints.*;

public record LoginRequest(

        @Email(message = "E-mail inválido")
        @NotBlank(message = "E-mail é obrigatório")
        @Size(max = 150, message = "E-mail deve ter no máximo 150 caracteres")
        String email,

        @NotBlank(message = "Senha é obrigatória")
        @Size(min = 6, max = 72, message = "Senha deve ter entre 6 e 72 caracteres")
        String senha
) {}
