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
