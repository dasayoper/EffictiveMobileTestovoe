package by.dasayoper.taskmanager.security.filters;

import by.dasayoper.taskmanager.exception.UserAccountNotFoundException;
import by.dasayoper.taskmanager.security.utils.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private static final String LOGIN_URL = "/auth/login";
    private final ObjectMapper objectMapper;
    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().equals(LOGIN_URL)) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = jwtUtils.extractToken(request);
        if (token != null) {
            try {
                if (jwtUtils.validateToken(token) && !jwtUtils.isTokenBlacklisted(token)) {
                    Authentication authentication = jwtUtils.getAuthentication(token);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    filterChain.doFilter(request, response);
                } else {
                    sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "Срок действия токена истек или токен невалиден");
                }
            } catch (UserAccountNotFoundException e) {
                sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "Нет подходящих данных для авторизации для указанного токена");
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private void sendErrorResponse(HttpServletResponse response, int status, String errorMessage) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status);
        objectMapper.writeValue(response.getWriter(), Collections.singletonMap("error", errorMessage));
    }
}

