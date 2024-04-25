# Spring Security e Json Web Token (JWT)

## Classes e Interfaces utilizadas: 

## Interface `UserDetails` e `UserDetailsService`

A interface `UserDetails` é parte do framework Spring Security e representa o usuário autenticado. Ele contém detalhes como o nome de usuário, senha, autoridades (funções), e outros atributos. A interface `UserDetails` tem vários métodos, incluindo:

* `getUsername()`: Retorna o nome de usuário do usuário.
* `getPassword()`: Retorna a senha do usuário.
* `getAuthorities()`: Retorna uma coleção de objetos `GrantedAuthority` que representam as funções e permissões do usuário.
* `isAccountNonExpired()`: Retorna se a conta do usuário não expirou.
* `isAccountNonLocked()`: Retorna se a conta do usuário não está trancada.
* `isCredentialsNonExpired()`: Retorna se as credenciais do usuário não expiraram.
* `isEnabled()`: Retorna se o usuário está habilitado.

A interface `UserDetailsService` é usada pelo `DaoAuthenticationProvider` para recuperar um nome de usuário, uma senha e outros atributos para autenticação com um nome de usuário e senha. Ele tem um único método chamado `loadUserByUsername(String username)` que recebe um nome de usuário como parâmetro e retorna um objeto `UserDetails` totalmente populado.

O Spring Security fornece implementações em memória e JDBC da `UserDetailsService`. Você pode definir autenticação personalizada expostando um `UserDetailsService` personalizado como um bean. A interface `UserDetailsService` é usada em todo o framework como um objeto de acesso a dados (DAO) e é a estratégia usada pelo `DaoAuthenticationProvider`. A interface requer apenas um método de leitura somente, o que simplifica o suporte para novas estratégias de acesso a dados.

Em resumo, a interface `UserDetails` representa o usuário autenticado no framework Spring Security, e a interface `UserDetailsService` é usada para carregar dados específicos do usuário para autenticação.


## Classe `OncePerRequestFilter`

A classe `OncePerRequestFilter` é uma classe abstrata no framework Spring que fornece uma implementação conveniente da interface `Filter`. Ele garante que o filtro seja invocado apenas uma vez por solicitação, mesmo que a solicitação seja encaminhada várias vezes dentro da mesma sessão HTTP.

A classe `OncePerRequestFilter` é projetada para ser usada com o framework Spring MVC e é frequentemente usada para executar tarefas que precisam ser executadas uma vez por solicitação, como autenticação e autorização.

Para usar a classe `OncePerRequestFilter`, você precisa substituir o método `doFilterInternal()`, que é chamado uma vez por solicitação. O método recebe três parâmetros: `ServletRequest`, `ServletResponse`, e `FilterChain`. O método `doFilterInternal()` deve chamar o método `doFilter()` do objeto `FilterChain` para passar a solicitação e a resposta para o próximo filtro na cadeia.

A classe `OncePerRequestFilter` fornece vários métodos que podem ser usados para personalizar o comportamento do filtro, como `shouldNotFilter()` e `shouldFilter()`. O método `shouldNotFilter()` é usado para determinar se o filtro deve ser invocado para uma solicitação específica, e o método `shouldFilter()` é usado para determinar se o filtro deve ser invocado em absoluto.

Em resumo, a classe `OncePerRequestFilter` é uma classe abstrata no framework Spring que fornece uma implementação conveniente da interface `Filter`. Ele garante que o filtro seja invocado apenas uma vez por solicitação e é frequentemente usado para executar tarefas que precisam ser executadas uma vez por solicitação, como autenticação e autorização. A classe fornece vários métodos que podem ser usados para personalizar o comportamento do filtro.


## Classe `UsernamePasswordAuthenticationFilter`

A classe `UsernamePasswordAuthenticationFilter` é uma classe do Spring Security que cuida da autenticação de um usuário com base em um nome de usuário e senha enviados em uma solicitação HTTP. É um filtro que geralmente é configurado como parte de uma cadeia de filtros do Spring Security e é responsável por processar solicitações de autenticação enviadas via formulários HTTP ou solicitações AJAX.

A `UsernamePasswordAuthenticationFilter` fornece vários métodos para personalizar seu comportamento, incluindo métodos para especificar a URL de login, os nomes dos parâmetros de nome de usuário e senha e os manipuladores de sucesso e falha. O filtro também fornece um método para validar as credenciais enviadas e criar um objeto `Authentication` se as credenciais forem válidas.

Quando um usuário envia uma solicitação de login, o `UsernamePasswordAuthenticationFilter` intercepta a solicitação e tenta autenticar o usuário. Se a autenticação for bem-sucedida, o filtro cria um objeto `Authentication` e adiciona-o ao contexto de segurança. Se a autenticação falhar, o filtro pode retornar uma resposta de erro ou redirecionar o usuário para uma página de falha de login.

A `UsernamePasswordAuthenticationFilter` é uma parte importante do mecanismo de autenticação do Spring Security e é frequentemente usada em conjunto com outros filtros e provedores de autenticação para fornecer uma solução de segurança completa para aplicativos web. É uma classe flexível e personalizável que pode ser ajustada para atender às necessidades específicas de diferentes aplicativos e casos de uso.


## Interface `AuthenticationProvider`

`AuthenticationProvider` é uma interface no Spring Security que define um contrato para realizar a autenticação. Ele é responsável por autenticar um usuário com base no objeto `Authentication` fornecido, que geralmente contém um nome de usuário e senha.

A interface `AuthenticationProvider` tem um único método, `authenticate(Authentication authentication)`, que recebe um objeto `Authentication` como parâmetro e retorna um objeto `Authentication` que representa o usuário autenticado. Se a autenticação falhar, o método deve lançar uma exceção `AuthenticationException`.

O Spring Security fornece várias implementações da interface `AuthenticationProvider`, incluindo `DaoAuthenticationProvider`, que autentica usuários com base em dados armazenados em um banco de dados, e `LdapAuthenticationProvider`, que autentica usuários contra um servidor LDAP.

Também é possível criar implementações personalizadas da interface `AuthenticationProvider` para suportar mecanismos de autenticação personalizados. Para criar um `AuthenticationProvider` personalizado, você precisa implementar a interface `AuthenticationProvider` e fornecer uma implementação para o método `authenticate`.

A interface `AuthenticationProvider` é um componente chave do mecanismo de autenticação do Spring Security. Ele é responsável por realizar a autenticação real de um usuário com base no objeto `Authentication` fornecido. Fornecendo implementações personalizadas da interface `AuthenticationProvider`, os desenvolvedores podem estender o mecanismo de autenticação do Spring Security para suportar mecanismos de autenticação personalizados.


## Classe `AuthenticationManager`

A classe `AuthenticationManager` é uma interface fundamental no Spring Security que desempenha um papel crucial no processo de autenticação de usuários. Ela é responsável por autenticar as credenciais de um usuário, verificando se representam um usuário válido. A interface `AuthenticationManager` possui um único método, `authenticate(Authentication authentication)`, que recebe um objeto `Authentication` como parâmetro e retorna um objeto `Authentication` representando o usuário autenticado.

O `AuthenticationManager` é o principal ponto de entrada para o processo de autenticação no Spring Security. Ele pode realizar uma das três ações em seu método `authenticate()`: retornar um objeto `Authentication` com `authenticated=true` se as credenciais forem válidas, lançar uma exceção `AuthenticationException` se as credenciais forem inválidas ou retornar `null` se não puder decidir.

Essa classe desempenha um papel crucial na separação da autenticação da autorização no Spring Security, garantindo que a autenticação seja tratada de forma independente. Ela é frequentemente utilizada em conjunto com diferentes provedores de autenticação, como `DaoAuthenticationProvider` e `LdapAuthenticationProvider`, para validar as credenciais dos usuários em diferentes contextos de autenticação.

Em resumo, o `AuthenticationManager` é uma interface essencial no Spring Security que gerencia o processo de autenticação de usuários, verificando se as credenciais fornecidas são válidas. Ele desempenha um papel central na autenticação de usuários e é fundamental para garantir a segurança e o controle de acesso em aplicações web protegidas pelo Spring Security.


## Classe `PasswordEncoder`

A classe `PasswordEncoder` é uma interface no Spring Security que é usada para codificar e verificar senhas de forma segura. Ela fornece métodos para codificar senhas antes de armazená-las em um banco de dados e para verificar se uma senha fornecida corresponde à senha armazenada após a codificação.

O principal objetivo do `PasswordEncoder` é garantir a segurança das senhas dos usuários, protegendo-as contra ataques de segurança, como ataques de força bruta e vazamento de senhas em texto simples. Ele ajuda a proteger as informações confidenciais dos usuários, garantindo que as senhas sejam armazenadas de forma segura e não reversível.

O Spring Security fornece várias implementações da interface `PasswordEncoder`, como o `BCryptPasswordEncoder`, `StandardPasswordEncoder`, `NoOpPasswordEncoder`, entre outros. Cada implementação oferece diferentes níveis de segurança e complexidade na codificação das senhas.

Em resumo, a classe `PasswordEncoder` é uma interface no Spring Security usada para codificar e verificar senhas de forma segura. Ela desempenha um papel crucial na proteção das informações confidenciais dos usuários e na garantia da segurança das senhas armazenadas em um sistema. É uma ferramenta essencial para garantir a segurança e a integridade dos dados de autenticação em aplicações web protegidas pelo Spring Security.


## classe `BCryptPasswordEncoder`

A classe `BCryptPasswordEncoder` é uma classe no Spring Security que implementa a interface `PasswordEncoder`. Ele usa a função de hash BCrypt forte para codificar e verificar senhas. BCrypt é uma função de hash de senha projetada para ser computacionalmente cara e resistente a ataques como ataques de tabelas arco-íris e ataques de força bruta.

A classe `BCryptPasswordEncoder` fornece vários construtores que permitem configurar o número de rodadas de log usadas na função BCrypt. As rodadas de log determinam o custo computacional da hash de uma senha, com um número maior de rodadas de log resultando em um hash mais seguro, mas mais lento.

O método `encode` da classe `BCryptPasswordEncoder` é usado para codificar uma senha bruta em um hash BCrypt. O método `matches` é usado para verificar se uma senha bruta fornecida corresponde a um hash BCrypt armazenado.

A classe `BCryptPasswordEncoder` gera hashes diferentes para a mesma senha porque ela inclui um sal aleatório no hash. Isso é uma característica de segurança que torna mais difícil para os atacantes usar tabelas pré-computadas de hashes (tabelas arco-íris) para quebrar senhas.

A classe `BCryptPasswordEncoder` é uma maneira segura e recomendada de codificar e verificar senhas em aplicativos Spring Security. Ela é amplamente usada na indústria e foi amplamente testada e revisada por especialistas em segurança.

# Documentação Projeto Spring Security Demo 3

## Pacote de Entity

### Classe `OurUsers`

```java
package com.apirest.springsecuritydemo3.entities;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "ourusers")
public class OurUsers implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String email;
    private String password;
    private String role;

    // Métodos do UserDetails

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role));
    }

    @Override
    public String getUsername() {
        return email;
    }

    public String getPassword(){
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

A classe `OurUsers` é uma entidade JPA que representa um usuário no sistema. Ela implementa a interface `UserDetails` do Spring Security, fornecendo informações de autenticação e autorização do usuário. A classe possui atributos como ID, email, senha e função, e implementa os métodos da interface `UserDetails` para fornecer informações de autoridade, nome de usuário e status do usuário. Além disso, a classe é anotada com `@Entity` e `@Table` para mapear a entidade para uma tabela no banco de dados.

### classe `Product`

```java
package com.apirest.springsecuritydemo3.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "products")
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String name;

}
```

A classe `Product` é uma entidade JPA que representa um produto no sistema. Ela é anotada com `@Entity` e `@Table` para mapear a entidade para uma tabela no banco de dados. A classe possui atributos como ID e nome do produto, e é anotada com `@Id` e `@GeneratedValue` para gerar automaticamente o valor do ID. Além disso, a classe é anotada com `@Data` para gerar automaticamente os métodos getter, setter, equals, hashCode e toString.

## Pacote DTO
### Classe `ReqRes`

```java
package com.apirest.springsecuritydemo3.dtos;

import java.util.List;

import com.apirest.springsecuritydemo3.entities.OurUsers;
import com.apirest.springsecuritydemo3.entities.Product;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ReqRes {

    private int statusCode;
    private String error;
    private String message;
    private String token;
    private String refreshToken;
    private String expirationTime;
    private String name;
    private String email;
    private String role;
    private String password;
    private List<Product> products;
    private OurUsers ourUsers;

}
```

A classe `ReqRes` é um modelo de dados que representa uma resposta genérica em um sistema. Ela contém campos como código de status, mensagem de erro, mensagem, token de autenticação, token de atualização, tempo de expiração, nome, email, função, senha, lista de produtos e informações de usuário. Essa classe é utilizada para estruturar e transportar informações entre diferentes partes do sistema de forma organizada e coesa.

## Pacote Repository
### Classes `OurUsersRepository` e `ProductRepository`

```java
package com.apirest.springsecuritydemo3.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.apirest.springsecuritydemo3.entities.OurUsers;

@Repository
public interface OurUsersRepository extends JpaRepository<OurUsers, Integer>{
    Optional<OurUsers> findByEmail(String email);
}
```

```java
package com.apirest.springsecuritydemo3.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.apirest.springsecuritydemo3.entities.Product;

@Repository
public interface ProductRepository extends JpaRepository<Product, Integer>{
    
}
```

As classes `OurUsersRepository` e `ProductRepository` são repositórios de acesso a dados que usam a interface `JpaRepository` do Spring Data JPA para fornecer operações de CRUD básicas em bancos de dados relacionais. A anotação `@Repository` indica que essas classes são repositórios de dados e devem ser registradas como beans no contêiner de injeção de dependência do Spring.

A classe `OurUsersRepository` estende `JpaRepository<OurUsers, Integer>` para fornecer operações de CRUD para a entidade `OurUsers`, enquanto a classe `ProductRepository` estende `JpaRepository<Product, Integer>` para fornecer operações de CRUD para a entidade `Product`. Além disso, a classe `OurUsersRepository` define um método personalizado `findByEmail` que retorna um `Optional<OurUsers>` com o usuário que tem o email especificado.


## Pacote Service

### Classe `OurUserDetailsService`

A classe `OurUserDetailsService` é um serviço que implementa a interface `UserDetailsService` do Spring Security para carregar detalhes do usuário durante o processo de autenticação. Ela é anotada com `@Service` para indicar que é um componente de serviço gerenciado pelo Spring.

- **Funcionalidade Principal:**
  - **loadUserByUsername:** Método que carrega um usuário com base no seu nome de usuário (email neste caso).
    - Utiliza o `OurUsersRepository` para buscar um usuário pelo email fornecido.
    - Se o usuário não for encontrado, lança uma exceção `UsernameNotFoundException` com uma mensagem indicando o nome de usuário que não foi encontrado.


### Classe `JWTUtils`

```java
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
        String secretString = "843567893696976453275974432697R634976R738467TR678T34865R6834R8763T478378637664538745673865783678548735687R3"; 
        byte[] keyBytes = Base64.getDecoder().decode(secretString.getBytes(StandardCharsets.UTF_8));                                         
        this.key = new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    /*Método que gera o token JWT. Ele constrói e assina o JWT usando o objeto Key e o nome de usuário do usuário.*/
    public String generateToken(UserDetails userDetails){
        return Jwts.builder()                                                            
                .subject(userDetails.getUsername())                                     
                .issuedAt(new Date(System.currentTimeMillis()))                          
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))      
                .signWith(key)                                                           
                .compact();                                                              
    }

    /*Método que gera um token de atualização JWT com reivindicações adicionais. Ou seja, gera um token de atualização JWT com reivindicações adicionais para um usuário usando uma chave secreta. O método constrói e assina o JWT usando o objeto key, o nome de usuário do usuário e as reivindicações adicionais. O parâmetro claims é um HashMap de dados adicionais que serão incluídos no JWT.*/
    public String generateRefreshToken(HashMap<String, Object> claims, UserDetails userDetails){
        return Jwts.builder()                                                            
                . claims(claims)                                                         
                .subject(userDetails.getUsername())                                      
                .issuedAt(new Date(System.currentTimeMillis()))                          
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))      
                .signWith(key)                                                           
                .compact();                                                              
    }

    /*Método que extrai o nome de usuário de um token JWT.*/
    public String extractUsername(String token){
        return extractClaims(token, Claims::getSubject);                                 
    }

    /*Método privado que extrai uma reivindicação específica de um token JWT.*/
    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction){
        return claimsTFunction.apply(Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload());  
    }

    /*Método que verifica se um token JWT é válido. Ele extrai o nome de usuário do token JWT e verifica se corresponde ao nome de usuário do parâmetro userDetails e se o token não está expirado usando o método isTokenExpired.*/
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);                                       
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));        
    }

    /*Método que verifica se um token JWT está expirado.*/
    public boolean isTokenExpired(String token){
        return extractClaims(token, Claims::getExpiration).before(new Date());              
    }

}

```

A classe `JWTUtils` é responsável pela geração, validação e manipulação de tokens JWT (JSON Web Tokens) para autenticação e autorização de usuários em um sistema. Ela possui métodos para:

* Inicializar uma chave secreta para assinar os tokens;
* Gerar um token JWT assinado com o nome de usuário do usuário e uma data de expiração;
* Gerar um token de atualização JWT com reivindicações adicionais;
* Extrair o nome de usuário de um token JWT;
* Extrair uma reivindicação específica de um token JWT;
* Verificar se um token JWT é válido, verificando se o nome de usuário corresponde ao do parâmetro `UserDetails` e se o token não está expirado;
* Verificar se um token JWT está expirado.



### Classe `AuthService`

A classe `AuthService` é responsável pela autenticação e autorização de usuários em um sistema. Ela contém métodos para realizar o login, o refresh de token e o logout de usuários.

```java
package com.apirest.springsecuritydemo3.service;

import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.apirest.springsecuritydemo3.dtos.ReqRes;
import com.apirest.springsecuritydemo3.entities.OurUsers;
import com.apirest.springsecuritydemo3.repositories.OurUsersRepository;

@Service
public class AuthService {

    @Autowired
    private OurUsersRepository ourUsersRepository;

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

   
    public ReqRes signUp(ReqRes registrationRequest) {

        ReqRes resp = new ReqRes();

        try {
            OurUsers ourUsers = new OurUsers();
            ourUsers.setEmail(registrationRequest.getEmail());                                     
            ourUsers.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));       
            ourUsers.setRole(registrationRequest.getRole());                                      
            OurUsers ourUserResult = ourUsersRepository.save(ourUsers);

            if (ourUserResult != null && ourUserResult.getId() > 0) {
                resp.setOurUsers(ourUserResult);
                resp.setMessage("User Saved Successfully");
                resp.setStatusCode(200);
            }
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setError(e.getMessage());
        }
        return resp;
    }


    public ReqRes signIn(ReqRes signinRequest){
            
        ReqRes response = new ReqRes();

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signinRequest.getEmail(),signinRequest.getPassword()));
            var user = ourUsersRepository.findByEmail(signinRequest.getEmail())                                                                 
                            .orElseThrow(() -> new RuntimeException("Usuário com email " + signinRequest.getEmail() + " inexistente!"));        
            System.out.println("USER IS: "+ user);
            var jwt = jwtUtils.generateTok(user);                                                                                                
            var refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), user);                                                               
            response.setStatusCode(200);                                                                                                
            response.setToken(jwt);                                                                                                                
            response.setRefreshToken(refreshToken);                                                                                                
            response.setExpirationTime("24Hr");                                                                                     
            response.setMessage("Login bem-sucedido");
        }catch (Exception e){
            response.setStatusCode(500);
            response.setError(e.getMessage());
            }
        return response;                                                                                                                            
    }

    public ReqRes refreshToken(ReqRes refreshTokenReqiest){
            
        ReqRes response = new ReqRes();
            
        String ourEmail = jwtUtils.extractUsername(refreshTokenReqiest.getToken());  
        OurUsers users = ourUsersRepository.findByEmail(ourEmail)
                            .orElseThrow(() -> new RuntimeException("Usuário com email " + refreshTokenReqiest.getEmail() + " inexistente!"));
            
        if (jwtUtils.isTokenValid(refreshTokenReqiest.getToken(), users)) { 
            var jwt = jwtUtils.generateToken(users);                                   
            response.setStatusCode(200);                                     
            response.setToken(jwt);                                                    
            response.setRefreshToken(refreshTokenReqiest.getToken());                  
            response.setExpirationTime("24Hr");                          
            response.setMessage("Successfully Refreshed Token");
        }
        response.setStatusCode(500);                                         
        return response;                                                               
    }
}

```

O método `signUp` é responsável por criar um novo usuário no sistema, validando os dados fornecidos e salvando-os no banco de dados.

O método `signIn` é responsável por autenticar as credenciais do usuário, gerar um token JWT e um token de atualização, e retornar uma resposta com as informações do token e o status de sucesso.

O método `refreshToken` é responsável por validar o token de atualização, gerar um novo token JWT e retornar uma resposta com as informações do token e o status de sucesso.

Em resumo, a classe `AuthService` é responsável por gerenciar o acesso de usuários ao sistema, validando suas credenciais e gerenciando os tokens de autenticação.


## Pacote de Configuration

### Classe `SecurityConfig`

```java
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
        httpSecurity.csrf(AbstractHttpConfigurer::disable)                                                                      
                .cors(Customizer.withDefaults())                                                                                
                .authorizeHttpRequests(request -> request.requestMatchers("/auth/**", "/public/**").permitAll()     
                        .requestMatchers("/admin/**").hasAnyAuthority("ADMIN")                       
                        .requestMatchers("/user/**").hasAnyAuthority("USER")                         
                        .requestMatchers("/adminuser/**").hasAnyAuthority("USER", "ADMIN")           
                        .anyRequest().authenticated())                                                                          
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))                   
                .authenticationProvider(authenticationProvider()).addFilterBefore(                                              
                        jwtAuthFIlter, UsernamePasswordAuthenticationFilter.class                                  
                );
        return httpSecurity.build();                                                                                            
    }

    /*Método indica que ele retorna um bean AuthenticationProvider.*/
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(ourUserDetailsService);                     
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());                            
        return daoAuthenticationProvider;
    }

    /*Método indica que ele retorna um bean PasswordEncoder.*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();                                                          
    }

    /*Método indica que ele retorna um bean AuthenticationManager.*/
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();                              
    }

}

```

A classe `SecurityConfig` é uma configuração de segurança para a aplicação web. Ela define as regras de autorização e autenticação para as solicitações HTTP. A classe é anotada com `@Configuration` e `@EnableWebSecurity` para indicar que é uma configuração de segurança para a aplicação web.

A classe tem um `SecurityFilterChain` bean definido no método `securityFilterChain`. Este método define as regras de autorização e autenticação para as solicitações HTTP. Ele desativa a proteção CSRF, permite o acesso sem autenticação aos caminhos `/auth/**` e `/public/**`, restringe o acesso aos caminhos `/admin/**` aos utilizadores com a autoridade `ADMIN`, restringe o acesso aos caminhos `/user/**` aos utilizadores com a autoridade `USER`, restringe o acesso aos caminhos `/adminuser/**` aos utilizadores com a autoridade `USER` ou `ADMIN`, e requer autenticação para todas as outras solicitações.

A classe também tem um `AuthenticationProvider` bean definido no método `authenticationProvider`. Este método define o provedor de autenticação para a aplicação. Ele usa o `DaoAuthenticationProvider` com o `UserDetailsService` definido como `ourUserDetailsService` e o `PasswordEncoder` definido como `BCryptPasswordEncoder`.

Além disso, a classe tem um `PasswordEncoder` bean definido no método `passwordEncoder`. Este método cria uma nova instância de `BCryptPasswordEncoder` e a retorna como o bean `PasswordEncoder`.

Por fim, a classe tem um `AuthenticationManager` bean definido no método `authenticationManager`. Este método recupera o `AuthenticationManager` do `AuthenticationConfiguration` e o retorna como o bean `AuthenticationManager`.

### Classe `JWTAuthFIlter`

```java
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

    /*Método verifica se o cabeçalho Authorization está presente, extrai o token JWT, valida o token e define o contexto de segurança se o token for válido. Se o token não estiver presente ou for inválido, a cadeia de filtros será invocada e o método retornará.*/
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");               
        final String jwtToken;
        final String userEmail;

        if (authHeader == null || authHeader.isBlank()) {                                
            filterChain.doFilter(request, response);
            return;
        }

        jwtToken = authHeader.substring(7);                                   
        userEmail = jwtUtils.extractUsername(jwtToken);                                  
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {        
            UserDetails userDetails = ourUserDetailsService.loadUserByUsername(userEmail);                

            if (jwtUtils.isTokenValid(jwtToken, userDetails)) {                                           
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();             
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());                                                       
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);
            }
        }
        filterChain.doFilter(request, response);                                          
    }
}

```

A classe `JWTAuthFIlter` é um filtro HTTP personalizado que é responsável por autenticar usuários com base em um token JWT (JSON Web Token) fornecido no cabeçalho de autorização da solicitação HTTP. Ele estende a classe `OncePerRequestFilter` e implementa o método `doFilterInternal()` para realizar a autenticação.

O filtro primeiro verifica se o cabeçalho de autorização está presente na solicitação HTTP. Se o cabeçalho não estiver presente, o filtro simplesmente invoca a cadeia de filtros seguinte e retorna. Se o cabeçalho estiver presente, o filtro extrai o token JWT do cabeçalho, extrai o endereço de email do usuário do token e verifica se o token é válido usando a classe `JWTUtils`.

Se o token for válido, o filtro cria um novo contexto de segurança, define o token de autenticação e define o contexto de segurança no thread atual. Em seguida, o filtro invoca a cadeia de filtros seguinte.

Em resumo, a classe `JWTAuthFIlter` é responsável por autenticar usuários com base em um token JWT fornecido no cabeçalho de autorização da solicitação HTTP e por definir o contexto de segurança se o token for válido.

## Pacote Controller

### Classe `AuthController`

```java
package com.apirest.springsecuritydemo3.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.apirest.springsecuritydemo3.dtos.ReqRes;
import com.apirest.springsecuritydemo3.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    // http://localhost:6060/auth/signup
    @PostMapping("/signup")
    public ResponseEntity<ReqRes> signUp(@RequestBody ReqRes signUpRequest){
        return ResponseEntity.ok(authService.signUp(signUpRequest));
    }

    // http://localhost:6060/auth/signin
    @PostMapping("/signin")
    public ResponseEntity<ReqRes> signIn(@RequestBody ReqRes signInRequest){
        return ResponseEntity.ok(authService.signIn(signInRequest));
    }

    // http://localhost:6060/auth/refresh
    @PostMapping("/refresh")
    public ResponseEntity<ReqRes> refreshToken(@RequestBody ReqRes refreshTokenRequest){
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest));
    }

}
```

A classe `AuthController` é um controlador REST que lida com as requisições relacionadas à autenticação de usuários. Ela é anotada com `@RestController` e mapeada para o caminho `/auth` através da anotação `@RequestMapping("/auth")`.

- **Métodos:**
  - **`signUp`:** Mapeado para `/auth/signup`, recebe uma requisição POST com um corpo de dados `ReqRes` para cadastrar um novo usuário. Chama o método `signUp` do serviço `authService` e retorna a resposta encapsulada em um `ResponseEntity`.
  
  - **`signIn`:** Mapeado para `/auth/signin`, recebe uma requisição POST com um corpo de dados `ReqRes` para autenticar um usuário. Chama o método `signIn` do serviço `authService` e retorna a resposta encapsulada em um `ResponseEntity`.
  
  - **`refreshToken`:** Mapeado para `/auth/refresh`, recebe uma requisição POST com um corpo de dados `ReqRes` para atualizar o token de autenticação. Chama o método `refreshToken` do serviço `authService` e retorna a resposta encapsulada em um `ResponseEntity`.

Em resumo, o `AuthController` fornece endpoints para cadastro de usuários, autenticação e atualização de tokens de autenticação, delegando o processamento das requisições ao serviço `authService` e retornando as respostas encapsuladas em `ResponseEntity`.


### Classe `AdminUsersController`

```java
package com.apirest.springsecuritydemo3.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.apirest.springsecuritydemo3.dtos.ReqRes;
import com.apirest.springsecuritydemo3.entities.Product;
import com.apirest.springsecuritydemo3.repositories.ProductRepository;

@RestController
public class AdminUsersController {

    @Autowired
    private ProductRepository productRepository;

    // http://localhost:6060/public/product
    @GetMapping("/public/product")
    public ResponseEntity<Object> getAllProducts(){
        return ResponseEntity.ok(productRepository.findAll());
    }

    // http://localhost:6060/admin/saveproduct
    @PostMapping("/admin/saveproduct")
    public ResponseEntity<Object> signUp(@RequestBody ReqRes productRequest){
        Product productToSave = new Product();
        productToSave.setName(productRequest.getName());
        return ResponseEntity.ok(productRepository.save(productToSave));
    }

    // http://localhost:6060/user/alone
    @GetMapping("/user/alone")
    public ResponseEntity<Object> userAlone(){
        return ResponseEntity.ok("Somente os usuários podem acessar esta API");
    }

    // http://localhost:6060/adminuser/both
    @GetMapping("/adminuser/both")
    public ResponseEntity<Object> bothAdminaAndUsersApi(){
        return ResponseEntity.ok("Tanto administradores quanto usuários podem acessar a API");
    }

    // http://localhost:6060/public/email
    /** Você pode usar isso para obter os detalhes (nome, email, função, ip, etc.) do usuário que acessa o serviço*/
    @GetMapping("/public/email")
    public String getCurrentUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(authentication); // obtenha todos os detalhes (nome, e-mail, senha, funções etc.) do usuário
        System.out.println(authentication.getDetails()); // obter ip remoto
        System.out.println(authentication.getName()); // retorna o email porque o email é o identificador exclusivo
        return authentication.getName(); // retorna o e-mail
    }
    
}
```

A classe `AdminUsersController` é um controlador REST que fornece endpoints para realizar operações relacionadas a produtos e usuários. Ele é anotado com `@RestController` e possui os seguintes métodos:

* `getAllProducts()`: retorna uma lista de todos os produtos cadastrados no banco de dados.
* `signUp(@RequestBody ReqRes productRequest)`: salva um novo produto no banco de dados com o nome recebido no corpo da requisição.
* `userAlone()`: retorna uma mensagem indicando que somente usuários autenticados podem acessar esta API.
* `bothAdminaAndUsersApi()`: retorna uma mensagem indicando que tanto administradores quanto usuários podem acessar esta API.
* `getCurrentUserEmail()`: retorna o e-mail do usuário autenticado que acessou o endpoint.

Além disso, a classe é mapeada para a URL base `/public` e possui um atributo `ProductRepository` injetado para realizar operações no banco de dados.

## pom.xml

```xml
        <dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
        <dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-test</artifactId>
			<scope>test</scope>
		</dependency>
        <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-impl -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.12.3</version>
            <scope>runtime</scope>
        </dependency>
		<!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-api -->
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>0.12.3</version>
		</dependency>
		<!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-jackson -->
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>0.12.3</version>
			<scope>runtime</scope>
		</dependency>
```

A biblioteca JJWT é uma implementação em Java de Tokens Web JSON (JWT) que permite a criação, análise e validação de JWTs. Ela inclui cinco componentes principais:

- `spring-boot-starter-security` adiciona as dependências necessárias para habilitar a segurança em uma aplicação Spring Boot.
- `spring-security-test` é usado para testes de unidade e integração de funcionalidades de segurança em aplicações Spring Boot.
- `jjwt-api`: Este módulo contém as interfaces de API para o processamento de JWT, que definem os métodos e classes que podem ser usados para criar, analisar e validar JWTs.
- `jjwt-impl`: Este módulo contém as classes de implementação para o processamento de JWT, que fornecem a funcionalidade real para criar, analisar e validar JWTs.
- `jjwt-jackson`: Este módulo fornece integração com a biblioteca de processamento JSON Jackson, o que permite uma serialização e desserialização mais fácil de JWTs.

Em conjunto, esses módulos fornecem uma solução abrangente para trabalhar com JWTs em aplicações Java. A biblioteca é amplamente utilizada e possui uma grande comunidade de usuários e contribuidores, tornando-a uma escolha confiável para o processamento de JWTs em Java. No entanto, é importante garantir que todas as dependências necessárias estejam incluídas no classpath da aplicação, pois a falta delas pode resultar em erros em tempo de execução.

---

# Autor
## Feito por: `Daniel Penelva de Andrade`