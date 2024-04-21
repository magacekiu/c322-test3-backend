package edu.iu.c322.test3.controllers;

import edu.iu.c322.test3.model.Customer;
import edu.iu.c322.test3.service.IAuthenticationService;
import edu.iu.c322.test3.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

@RestController
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final IAuthenticationService authenticationService;
    private TokenService tokenService;

    public AuthenticationController(AuthenticationManager authenticationManager,
                                    IAuthenticationService authenticationService,
                                    TokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.authenticationService = authenticationService;
        this.tokenService = tokenService;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> register(@RequestBody Customer customer) {
        try {
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            String encodedPassword = passwordEncoder.encode(customer.getPassword());
            customer.setPassword(encodedPassword);
            authenticationService.register(customer);
            return ResponseEntity.ok(true);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
    @PostMapping("/signin")
    public ResponseEntity<?> login(@RequestBody Customer customer) {
        try {
            System.out.println("Received login request for username: " + customer.getUsername());
            
            if (authenticationService.login(customer.getUsername(), customer.getPassword())) {
                System.out.println("Authentication successful for username: " + customer.getUsername());
                
                Authentication authentication = authenticationManager
                        .authenticate(
                                new UsernamePasswordAuthenticationToken(
                                        customer.getUsername(),
                                        customer.getPassword()));
                String token = tokenService.generateToken(authentication);
                return ResponseEntity.ok(token);
            } else {
                System.out.println("Authentication failed for username: " + customer.getUsername());
                
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
            }
        } catch (IOException e) {
            System.out.println("An error occurred during login: " + e.getMessage());
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred during login");
        }
    }
}

