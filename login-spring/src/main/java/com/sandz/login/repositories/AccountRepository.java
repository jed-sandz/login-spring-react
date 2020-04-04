package com.sandz.login.repositories;

import com.sandz.login.models.Account;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface AccountRepository extends MongoRepository<Account, String> {
    Account findByUsername(String username);
}
