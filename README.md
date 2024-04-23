# Interface `UserDetails` e `UserDetailsService`

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