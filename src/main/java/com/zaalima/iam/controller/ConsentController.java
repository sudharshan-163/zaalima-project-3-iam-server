package com.zaalima.iam.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ConsentController {

    @GetMapping("/oauth2/consent")
    public String consent() {
        return "consent";
    }
}
