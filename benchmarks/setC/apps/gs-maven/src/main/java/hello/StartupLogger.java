package hello;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class StartupLogger {

    private static final Logger LOGGER = LogManager.getLogger(StartupLogger.class);

    private StartupLogger() {
    }

    public static void logStartup() {
        LOGGER.info("ReachSBOM Set C startup marker: gs-maven");
    }
}
