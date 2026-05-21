package com.challenge.AuthApi.dto;

public record AuthResponse(
        String token,
        String nome,
        String email
) {}