package by.dasayoper.taskmanager.security.filters;

import by.dasayoper.taskmanager.security.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtLogoutFilter extends OncePerRequestFilter {
    private static final String LOGOUT_URL = "/auth/logout";

    private final static RequestMatcher logoutRequest = new AntPathRequestMatcher(LOGOUT_URL, "POST");
    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if (logoutRequest.matches(request)) {
            String token = jwtUtils.extractToken(request);
            if (token != null) {
                jwtUtils.blacklistToken(token);
                SecurityContextHolder.clearContext();
                sendResponse(response, HttpServletResponse.SC_OK, "Успешный выход из системы, токен записан в blacklist");
            } else {
                sendResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Ошибка, отсутствует токен");
            }
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void sendResponse(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");

        response.getWriter().write(message);
    }
}


