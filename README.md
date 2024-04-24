# Spring Security e Json Web Token (JWT)

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