package com.springproject.springbootsecurity.controller;

import ch.qos.logback.core.net.SyslogOutputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;

@Controller
public class ProjectController {


    @GetMapping("/home")
    @ResponseBody
    public String home() {
        return "home";
    }

    @RequestMapping("/test")
   public ResponseEntity<String> hashingPasswords() {

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String[] passwords = {
                "password123",
                "password456",
                "password789",
                "dundermifflin",
                "artsytartsy",
                "prankmaster",
                "beetfarmer",
                "passworddonuts",
                "crosswordpuzzle",
                "catlady",
                "narddog",
                "accountingwiz",
                "temp123",
                "fashionista",
                "hrnightmare",
                "mysteryman"
        };

        String hashedPassword = null;
        for (String password : passwords) {
            hashedPassword = encoder.encode(password);
            System.out.println(hashedPassword);
        }
        return ResponseEntity.ok(hashedPassword);
    }


}
