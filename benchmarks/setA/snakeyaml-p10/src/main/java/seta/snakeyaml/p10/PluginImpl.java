package seta.snakeyaml.p10;

import seta.spi.Plugin;

public final class PluginImpl implements Plugin {
    @Override
    public void run() {
        Object o = new org.yaml.snakeyaml.Yaml().load("a: 1");
    }
}
