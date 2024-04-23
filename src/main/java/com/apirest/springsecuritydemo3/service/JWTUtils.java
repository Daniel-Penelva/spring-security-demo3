package com.apirest.springsecuritydemo3.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JWTUtils {

    private SecretKey key;
    private static final long EXPIRATION_TIME = 86400000; // 24 horas ou 86400000 milessegundos

    /*Construtor inicializa a chave secreta e cria um objeto Key*/
    public JWTUtils() {
        String secretString = "843567893696976453275974432697R634976R738467TR678T34865R6834R8763T478378637664538745673865783678548735687R3"; // Inicializa uma variável de string chamada secreteString com uma chave secreta gerada aleatoriamente.
        byte[] keyBytes = Base64.getDecoder().decode(secretString.getBytes(StandardCharsets.UTF_8));                                         // converte a string secreta em bytes usando a codificação UTF-8 e, em seguida, decodifica os bytes resultantes usando a decodificação Base64.
        this.key = new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    /*Método que gera o token JWT. Ele constrói e assina o JWT usando o objeto Key e o nome de usuário do usuário.*/
    public String generateToken(UserDetails userDetails){
        return Jwts.builder()                                                            // cria um novo construtor JWT usando a classe Jwts
                .subject(userDetails.getUsername())                                      // define o assunto do JWT como o nome de usuário do usuário.
                .issuedAt(new Date(System.currentTimeMillis()))                          // define o tempo de emissão do JWT como o tempo atual.
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))      // define o tempo de expiração do JWT como o tempo atual mais a constante EXPIRATION_TIME.
                .signWith(key)                                                           // assina o JWT com o objeto Key.
                .compact();                                                              // cria a string JWT final compactando todas as configurações anteriores.
    }

    /*Método que gera um token de atualização JWT com reivindicações adicionais. Ou seja, gera um token de atualização JWT com reivindicações 
     *adicionais para um usuário usando uma chave secreta. O método constrói e assina o JWT usando o objeto key, o nome de usuário do usuário e 
     *as reivindicações adicionais. O parâmetro claims é um HashMap de dados adicionais que serão incluídos no JWT.*/
    public String generateRefreshToken(HashMap<String, Object> claims, UserDetails userDetails){
        return Jwts.builder()                                                            // cria um novo construtor JWT usando a classe Jwts.
                . claims(claims)                                                         // define as reivindicações do JWT para o parâmetro claims, que é um HashMap de dados adicionais.
                .subject(userDetails.getUsername())                                      // define o assunto do JWT como o nome de usuário do usuário.
                .issuedAt(new Date(System.currentTimeMillis()))                          // define o tempo de emissão do JWT como o tempo atual.
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))      // define o tempo de expiração do JWT como o tempo atual mais a constante EXPIRATION_TIME.
                .signWith(key)                                                           // assina o JWT com o objeto key, que se presume já estar inicializado.
                .compact();                                                              // cria a string JWT final compactando todas as configurações anteriores.
    }

    /*Método que extrai o nome de usuário de um token JWT.*/
    public String extractUsername(String token){
        return extractClaims(token, Claims::getSubject);                                 // chama o método extractClaims com o parâmetro token e uma função que extrai o assunto (nome de usuário) das reivindicações do JWT.
    }

    /*Método privado que extrai uma reivindicação específica de um token JWT.*/
    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction){
        return claimsTFunction.apply(Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload());  // analisa o token JWT, verifica-o com o objeto key, extrai a carga (que contém as reivindicações) e aplica a função claimsTFunction à carga para extrair a reivindicação desejada.
    }

    /*Método que verifica se um token JWT é válido. Ele extrai o nome de usuário do token JWT e verifica se corresponde ao nome de usuário do 
    *parâmetro userDetails e se o token não está expirado usando o método isTokenExpired.*/
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);                                       // extrai o nome de usuário do token JWT usando o método extractUsername.
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));        // verifica se o nome de usuário extraído corresponde ao nome de usuário do parâmetro userDetails e se o token não está expirado usando o método isTokenExpired.
    }

    /*Método que verifica se um token JWT está expirado.*/
    public boolean isTokenExpired(String token){
        return extractClaims(token, Claims::getExpiration).before(new Date());                // extrai a data de expiração do token JWT usando o método extractClaims e verifica se está antes da data atual usando o método before. 
    }

}
