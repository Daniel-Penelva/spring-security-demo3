package com.apirest.springsecuritydemo3.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.apirest.springsecuritydemo3.entities.OurUsers;

@Repository
public interface OurUsersRepository extends JpaRepository<OurUsers, Integer>{
    Optional<OurUsers> findByEmail(String email);
}
