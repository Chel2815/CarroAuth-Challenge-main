package com.challenge.AuthApi.dto;

public record ValidateTokenResponse(
        boolean valid,
        String email,
        String role
) {}