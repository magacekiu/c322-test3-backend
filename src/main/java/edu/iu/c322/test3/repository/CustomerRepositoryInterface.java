package edu.iu.c322.test3.repository;

import edu.iu.c322.test3.model.Customer;

import java.io.IOException;

public interface CustomerRepositoryInterface {
    boolean save(Customer customer) throws IOException;
    Customer findByUsername(String username) throws IOException;
}