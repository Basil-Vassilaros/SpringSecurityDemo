package com.clayton.SpringSecurityDemo.controller;

import com.clayton.SpringSecurityDemo.model.ERole;
import com.clayton.SpringSecurityDemo.model.Role;
import com.clayton.SpringSecurityDemo.model.User;
import com.clayton.SpringSecurityDemo.payload.request.SignupRequest;
import com.clayton.SpringSecurityDemo.payload.response.MessageResponse;
import com.clayton.SpringSecurityDemo.repository.RoleRepo;
import com.clayton.SpringSecurityDemo.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManagerManager;

    @Autowired
    UserRepo userRepo;

    @Autowired
    RoleRepo roleRepo;

    @Autowired
    PasswordEncoder passwordEncoder;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest){
        if(userRepo.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Username Already Taken"));
        }
        if(userRepo.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Email Already Taken"));
        }
        // Create new user's account
        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                passwordEncoder.encode(signupRequest.getUsername()));
        Set<String> strRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                    .orElseThrow(()-> new RuntimeException("Error: Role not found"));
            roles.add(userRole);
        } else {
            strRoles.forEach(
                    role -> {
                        switch (role) {
                            case "admin":
                                Role adminRole = roleRepo.findByName(ERole.ROLE_ADMIN)
                                        .orElseThrow(()-> new RuntimeException("Error: Role not found"));
                                roles.add(adminRole);
                                break;
                            case "mod":
                                Role modRole = roleRepo.findByName(ERole.ROLE_MODERATOR)
                                        .orElseThrow(()-> new RuntimeException("Error: Role not found"));
                                roles.add(modRole);
                                break;
                            default:
                                Role userRole = roleRepo.findByName(ERole.ROLE_USER)
                                        .orElseThrow(()-> new RuntimeException("Error: Role not found"));
                                roles.add(userRole);
                                break;
                        }

                    }
            );
        }
        user.setRoles(roles);
        userRepo.save(user);
        return ResponseEntity.ok( new MessageResponse("User registered successfully"));
    }
}


