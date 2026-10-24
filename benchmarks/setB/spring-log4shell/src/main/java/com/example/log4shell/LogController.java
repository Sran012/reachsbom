package com.example.log4shell;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogController {

    private static final Logger LOGGER = LogManager.getLogger(LogController.class);

    @GetMapping("/")
    public String index(@RequestParam(name = "input", required = false, defaultValue = "") String input) {
        LOGGER.info("Received input: {}", input);
        return "ok";
    }
}
