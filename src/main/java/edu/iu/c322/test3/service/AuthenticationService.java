package edu.iu.c322.test3.service;

import edu.iu.c322.test3.repository.CustomerRepository;
import edu.iu.c322.test3.model.Customer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.io.IOException;

@Service
public class AuthenticationService implements IAuthenticationService, UserDetailsService {
    private final CustomerRepository customerRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthenticationService(CustomerRepository customerRepository, BCryptPasswordEncoder passwordEncoder) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Customer register(Customer customer) throws IOException {
        if (customerRepository.save(customer)) {
            return customer;
        } else {
            throw new IOException("Failed to save customer");
        }
    }

    @Override
    public boolean login(String username, String password) throws IOException {
        System.out.println("Attempting login for username: " + username);
        
        Customer customer = customerRepository.findByUsername(username);
        if (customer != null) {
            System.out.println("Found customer with username: " + username);
            
            boolean isPasswordValid = passwordEncoder.matches(password, customer.getPassword());
            System.out.println("Password validation result: " + isPasswordValid);
            
            // Debug breakpoint
            // Add a breakpoint here to inspect the values of username, password, and isPasswordValid
            
            return isPasswordValid;
        }
        
        System.out.println("Customer not found with username: " + username);
        
        return false;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            Customer customer = customerRepository.findByUsername(username);
            if (customer == null) {
                throw new UsernameNotFoundException("User not found");
            }
            return User.withUsername(username)
                    .password(customer.getPassword())
                    .authorities("USER")
                    .build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}