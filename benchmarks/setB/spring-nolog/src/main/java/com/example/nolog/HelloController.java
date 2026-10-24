package com.example.nolog;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/")
    public String index(@RequestParam(name = "input", required = false, defaultValue = "") String input) {
        return "ok";
    }
}
