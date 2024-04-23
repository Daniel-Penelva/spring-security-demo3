package com.apirest.springsecuritydemo3.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.apirest.springsecuritydemo3.repositories.OurUsersRepository;

@Service
public class OurUserDetailsService implements UserDetailsService {

    @Autowired
    private OurUsersRepository ourUsersRepository;

    /* Método que carrega um usuário pelo seu nome de usuário. */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return ourUsersRepository.findByEmail(username)                                             // busca um usuário pelo seu e-mail usando o método findByEmail do objeto ourUsersRepository.
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado: " + username));    // Se o usuário não for encontrado, lança uma RuntimeException com uma mensagem indicando o nome de usuário que não foi encontrado. 
    }

}