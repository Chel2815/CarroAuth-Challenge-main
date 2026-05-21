package com.challenge.AuthApi.dto;

/**
 * Teste 4 — DTO de saída sem o campo senha.
 * Nunca expõe hash BCrypt nas respostas da API.
 */
public record UserResponse(
        Long id,
        String nome,
        String email,
        String role
) {}
