package com.sandz.login.controllers;

import com.sandz.login.models.Account;
import com.sandz.login.repositories.AccountRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(origins = "https://localhost:3000")
//@CrossOrigin(origins = "*") --if maraming frontend pero same backend

public class AccountController {
    @Autowired
    AccountRepository accountRepository;

    @GetMapping("/accounts")
    public Iterable<Account> getAccounts() {
        return accountRepository.findAll();
    }

    @Value("${jwt.secret}")
    private String secretKey;

    @PostMapping("/register")
    public String registerAccount(@RequestBody Account account) {
        Account foundAccount = accountRepository.findByUsername(account.getUsername());
        if(foundAccount==null) {
            String hashedpw = BCrypt.hashpw(account.getPassword(), BCrypt.gensalt());
            account.setPassword(hashedpw);
            accountRepository.save(account);
            return("registration successful");
        } else {
            return("username is already registered");
        }
    }

    @PostMapping("/login")
    public String loginAccount(@RequestBody Account account) {
        Account foundAccount = accountRepository.findByUsername(account.getUsername());

        if(BCrypt.checkpw(account.getPassword(), foundAccount.getPassword())) {
            Claims claims = Jwts.claims().setSubject(foundAccount.getId());
            return Jwts.builder()
                    .setClaims(claims)
                    .signWith(SignatureAlgorithm.HS512, secretKey)
                    .claim("account", foundAccount)
                    .compact();
        } else {
            return("It does not match");
        }
    }




}
