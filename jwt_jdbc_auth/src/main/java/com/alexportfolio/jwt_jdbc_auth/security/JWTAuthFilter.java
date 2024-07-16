package com.alexportfolio.jwt_jdbc_auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@AllArgsConstructor
@Component
public class JWTAuthFilter extends OncePerRequestFilter {
    TokenProcessor tokenProcessor;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = authHeader!=null ? authHeader.toLowerCase().contains("bearer") ? authHeader.substring(7) : null : null;
        Authentication auth = new AuthenticationObj();

        // extract authentication object from the token and put it to the security context. Or throw exception (handled by separate filter)
        if(token!=null && (auth = tokenProcessor.getAuthObjFromToken(token)) != null){
            SecurityContextHolder.getContext().setAuthentication(auth);

        }

        filterChain.doFilter(request,response);
    }
}
