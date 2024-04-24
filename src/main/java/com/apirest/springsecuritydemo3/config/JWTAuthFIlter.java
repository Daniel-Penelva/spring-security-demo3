package com.apirest.springsecuritydemo3.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.apirest.springsecuritydemo3.service.JWTUtils;
import com.apirest.springsecuritydemo3.service.OurUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTAuthFIlter extends OncePerRequestFilter {

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private OurUserDetailsService ourUserDetailsService;

    /*Método verifica se o cabeçalho Authorization está presente, extrai o token JWT, valida o token e define o contexto de segurança se o token 
     *for válido. Se o token não estiver presente ou for inválido, a cadeia de filtros será invocada e o método retornará.*/
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");               // obtém o valor do cabeçalho Authorization da solicitação.
        final String jwtToken;
        final String userEmail;

        if (authHeader == null || authHeader.isBlank()) {                                // verifica se o cabeçalho Authorization é nulo ou em branco. Se for, a cadeia de filtros é invocada e o método retorna.
            filterChain.doFilter(request, response);
            return;
        }

        jwtToken = authHeader.substring(7);                                   // extrai o token JWT do cabeçalho Authorization.
        userEmail = jwtUtils.extractUsername(jwtToken);                                  // extrai o endereço de email do token JWT usando o método extractUsername() da classe JWTUtils.

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {        // verifica se a variável userEmail não é nula e se o contexto de segurança está vazio
            UserDetails userDetails = ourUserDetailsService.loadUserByUsername(userEmail);                // carrega os detalhes do usuário do serviço OurUserDetailsService usando o método loadUserByUsername().

            if (jwtUtils.isTokenValid(jwtToken, userDetails)) {                                           // verifica se o token JWT é válido usando o método isTokenValid() da classe JWTUtils.
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();             // Esse bloco de código cria um novo contexto de segurança, cria um novo objeto, define os detalhes do token e define o contexto de segurança.
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());                                                       
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);
            }
        }
        filterChain.doFilter(request, response);                                          // invoca o próximo filtro na cadeia de filtros.
    }
}
