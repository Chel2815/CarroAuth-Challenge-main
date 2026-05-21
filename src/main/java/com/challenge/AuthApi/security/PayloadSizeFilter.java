package com.challenge.AuthApi.security;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;

import java.io.*;

/**
 * Lê no máximo MAX_BYTES do corpo e rejeita com 413 se ultrapassar.
 * Funciona mesmo quando o cliente não envia o header Content-Length.
 */
@Component
public class PayloadSizeFilter implements Filter {

    private static final int MAX_BYTES = 10 * 1024; // 10 KB

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  httpReq = (HttpServletRequest)  request;
        HttpServletResponse httpRes = (HttpServletResponse) response;

        // Lê o corpo inteiro, mas para em MAX_BYTES + 1
        byte[] body = readLimited(httpReq.getInputStream(), MAX_BYTES + 1);

        if (body.length > MAX_BYTES) {
            httpRes.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE); // 413
            httpRes.setContentType("application/json");
            httpRes.getWriter().write(
                "{\"error\": \"Payload excede o tamanho máximo permitido de 10KB.\"}"
            );
            return;
        }

        // Reembala o corpo já lido para o próximo filtro/controller
        chain.doFilter(new CachedBodyRequest(httpReq, body), response);
    }

    private byte[] readLimited(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[1024];
        int total = 0, read;

        while (total <= limit && (read = in.read(chunk)) != -1) {
            buf.write(chunk, 0, read);
            total += read;
        }
        return buf.toByteArray();
    }

    /** Wrapper que permite reler o body já consumido */
    private static class CachedBodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream bais = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                public int read() { return bais.read(); }
                public boolean isFinished() { return bais.available() == 0; }
                public boolean isReady()    { return true; }
                public void setReadListener(ReadListener l) {}
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream()));
        }
    }
}
