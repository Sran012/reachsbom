package seta.snakeyaml.p10;

import java.util.ServiceLoader;
import seta.spi.Plugin;

public final class App {
    private App() {
    }

    public static void main(String[] args) {
        ServiceLoader.load(Plugin.class).forEach(Plugin::run);
    }
}
