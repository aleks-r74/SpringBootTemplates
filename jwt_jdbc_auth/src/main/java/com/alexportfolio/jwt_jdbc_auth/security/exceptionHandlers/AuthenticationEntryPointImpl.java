package com.alexportfolio.jwt_jdbc_auth.security.exceptionHandlers;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;
// This class handles exception that occurs during authentication

@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{'error': '%s'\n 'suppressedExceptions' : '%s'}"
                .formatted(
                        authException.getMessage(),
                        Arrays.stream(authException.getSuppressed())
                                .map(e->e.getMessage())
                                .collect(Collectors.joining("\n"))
                )
        );
    }
}
