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

    /*
     * Método chamado signUp que recebe um objeto ReqRes como parâmetro e cria um  novo objeto OurUsers com o email, senha e função do objeto
     * ReqRes. Em seguida, salva o objeto OurUsers no banco de dados e retorna um objeto ReqRes com o objeto OurUsers salvo e uma mensagem de
     * sucesso se a operação de salvamento for bem-sucedida, ou uma mensagem de erro se uma exceção ocorrer.
     */
    public ReqRes signUp(ReqRes registrationRequest) {

        ReqRes resp = new ReqRes();

        try {
            OurUsers ourUsers = new OurUsers();
            ourUsers.setEmail(registrationRequest.getEmail());                                     // define o email do objeto ourUsers como o email do objeto registrationRequest.
            ourUsers.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));       // define a senha do objeto ourUsers como a senha codificada do objeto registrationRequest.
            ourUsers.setRole(registrationRequest.getRole());                                       // define o role do objeto ourUsers como o role do objeto registrationRequest.
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


    /*Método implementa a lógica de autenticação para um sistema de login. Ele verifica as credenciais do usuário, busca o usuário no banco de 
    *dados, gera um token JWT e um token de atualização, e retorna uma resposta com o status de sucesso e as informações do token. Se houver 
    *alguma exceção, o código define o status de erro e a mensagem de erro no objeto de resposta e retorna-a.*/
    public ReqRes signIn(ReqRes signinRequest){
        
        ReqRes response = new ReqRes();

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signinRequest.getEmail(),signinRequest.getPassword()));
            var user = ourUsersRepository.findByEmail(signinRequest.getEmail())                                                                   // O método authenticate é chamado no authenticationManager com um novo objeto UsernamePasswordAuthenticationToken que contém o email e a senha do objeto signinRequest. Isso verifica se as credenciais são válidas.
                            .orElseThrow(() -> new RuntimeException("Usuário com email " + signinRequest.getEmail() + " inexistente!"));        
            System.out.println("USER IS: "+ user);
            var jwt = jwtUtils.generateToken(user);                                                                                                // método generateToken é chamado no jwtUtils com o objeto user para gerar um token JWT.
            var refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), user);                                                               // método generateRefreshToken é chamado no jwtUtils com um novo mapa vazio e o objeto user para gerar um token de atualização.
            response.setStatusCode(200);                                                                                                // O código de status da resposta é definido como 200, indicando sucesso.
            response.setToken(jwt);                                                                                                                // o token JWT é definido no objeto response.
            response.setRefreshToken(refreshToken);                                                                                                // o token de atualização é definido no objeto response.
            response.setExpirationTime("24Hr");                                                                                     // o tempo de validade do token é definido como 24 horas no objeto response.
            response.setMessage("Login bem-sucedido");
        }catch (Exception e){
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;                                                                                                                            // A resposta é retornada como um objeto ReqRes.
    }


    /*Método implementa a lógica de atualização de token para um sistema de autenticação. Ele extrai o email do usuário do token de atualização, 
     *busca o usuário no banco de dados, verifica se o token de atualização é válido, gera um novo token JWT e retorna uma resposta com o status 
     *de sucesso e as informações do token. Se o token de atualização não for válido, o código define o status de erro no objeto de resposta e 
     *retorna-o.*/
    public ReqRes refreshToken(ReqRes refreshTokenReqiest){
        
        ReqRes response = new ReqRes();
        
        String ourEmail = jwtUtils.extractUsername(refreshTokenReqiest.getToken());     //método extractUsername é chamado no jwtUtils com o token de atualização do objeto refreshTokenReqiest para extrair o email do usuário do token. 
        OurUsers users = ourUsersRepository.findByEmail(ourEmail)
                            .orElseThrow(() -> new RuntimeException("Usuário com email " + refreshTokenReqiest.getEmail() + " inexistente!"));
        
        if (jwtUtils.isTokenValid(refreshTokenReqiest.getToken(), users)) {             // verifica se o token é válido
            var jwt = jwtUtils.generateToken(users);                                    // método generateToken é chamado no jwtUtils com o objeto users para gerar um novo token JWT.
            response.setStatusCode(200);                                     // código de status da resposta é definido como 200, indicando sucesso.
            response.setToken(jwt);                                                     // o novo token JWT é definido no objeto response.
            response.setRefreshToken(refreshTokenReqiest.getToken());                   // o token de atualização é definido no objeto response.
            response.setExpirationTime("24Hr");                          // o tempo de validade do token é definido como 24 horas no objeto response.
            response.setMessage("Successfully Refreshed Token");
        }
        response.setStatusCode(500);                                         // código de status da resposta é definido como 500, indicando um erro do servidor.
        return response;                                                                // a resposta é retornada como um objeto ReqRes.
    }
}
