package com.clayton.SpringSecurityDemo.repository;

import com.clayton.SpringSecurityDemo.model.ERole;
import com.clayton.SpringSecurityDemo.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
