package com.apirest.springsecuritydemo3.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.apirest.springsecuritydemo3.service.OurUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private OurUserDetailsService ourUserDetailsService;

    @Autowired
    private JWTAuthFIlter jwtAuthFIlter;

    /*Método que define a cadeia de filtros de segurança para a aplicação.*/
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(AbstractHttpConfigurer::disable)                                                                      // desativa a proteção Cross-Site Request Forgery (CSRF).
                .cors(Customizer.withDefaults())                                                                                // habilita a partilha de recursos entre origens cruzadas (CORS) com as definições padrão.
                .authorizeHttpRequests(request -> request.requestMatchers("/auth/**", "/public/**").permitAll()     // define as regras de autorização para as solicitações HTTP. Ele permite o acesso sem autenticação aos caminhos /auth/** e /public/**.
                        .requestMatchers("/admin/**").hasAnyAuthority("ADMIN")                       // restringe o acesso aos caminhos /admin/** aos utilizadores com a autoridade ADMIN.
                        .requestMatchers("/user/**").hasAnyAuthority("USER")                         // restringe o acesso aos caminhos /user/** aos utilizadores com a autoridade USER.
                        .requestMatchers("/adminuser/**").hasAnyAuthority("USER", "ADMIN")           // restringe o acesso aos caminhos /adminuser/** aos utilizadores com a autoridade USER ou ADMIN.
                        .anyRequest().authenticated())                                                                          // requer autenticação para todas as outras solicitações.
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))                   // define a política de criação de sessão para STATELESS, o que significa que a aplicação não criará ou gerenciará sessões de utilizador.
                .authenticationProvider(authenticationProvider()).addFilterBefore(                                              // define o provedor de autenticação para a aplicação.
                        jwtAuthFIlter, UsernamePasswordAuthenticationFilter.class                                  // adiciona o filtro de autenticação JWT antes do UsernamePasswordAuthenticationFilter.
                );
        return httpSecurity.build();                                                                                            // constrói e retorna a cadeia de filtros de segurança.
    }

    /*Método indica que ele retorna um bean AuthenticationProvider.*/
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(ourUserDetailsService);                     // define o UserDetailsService a ser usado pelo DaoAuthenticationProvider.
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());                            // define o PasswordEncoder a ser usado pelo DaoAuthenticationProvider.
        return daoAuthenticationProvider;
    }

    /*Método indica que ele retorna um bean PasswordEncoder.*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();                                                          // cria uma nova instância de BCryptPasswordEncoder e a retorna como o bean PasswordEncoder.
    }

    /*Método indica que ele retorna um bean AuthenticationManager.*/
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();                               // recupera o AuthenticationManager do AuthenticationConfiguration e o retorna como o bean AuthenticationManager.
    }

}
