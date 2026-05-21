package com.challenge.AuthApi.security;

import io.github.bucket4j.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Teste 2 — Proteção contra força bruta em /auth/login e /auth/register.
 * Teste 3 — Rate limiting geral para todas as rotas.
 *
 * Limites:
 *  - /auth/** → 10 req/minuto por IP (evita brute-force de senha)
 *  - demais   → 60 req/minuto por IP
 */
@Component
public class RateLimitFilter implements Filter {

    private final Map<String, Bucket> authBuckets    = new ConcurrentHashMap<>();
    private final Map<String, Bucket> generalBuckets = new ConcurrentHashMap<>();

    private Bucket createAuthBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1))))
                .build();
    }

    private Bucket createGeneralBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(60, Refill.greedy(60, Duration.ofMinutes(1))))
                .build();
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        return (xf != null) ? xf.split(",")[0].trim() : request.getRemoteAddr();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  req = (HttpServletRequest)  request;
        HttpServletResponse res = (HttpServletResponse) response;

        // Swagger / api-docs são isentos
        String path = req.getServletPath();
        if (path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs")) {
            chain.doFilter(request, response);
            return;
        }

        String ip = getClientIp(req);

        boolean isAuthPath = path.startsWith("/auth");
        Bucket bucket = isAuthPath
                ? authBuckets.computeIfAbsent(ip, k -> createAuthBucket())
                : generalBuckets.computeIfAbsent(ip, k -> createGeneralBucket());

        if (bucket.tryConsume(1)) {
            chain.doFilter(request, response);
        } else {
            res.setStatus(429);
            res.setContentType("application/json");
            res.getWriter().write(
                "{\"error\": \"Muitas requisições. Tente novamente em instantes.\"}"
            );
        }
    }
}
