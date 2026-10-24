package com.example.validatingforminput;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class StartupLogger implements ApplicationRunner {

    private static final Logger LOGGER = LogManager.getLogger(StartupLogger.class);

    @Override
    public void run(ApplicationArguments args) {
        LOGGER.info("ReachSBOM Set C startup marker: gs-validating-form-input");
    }
}
