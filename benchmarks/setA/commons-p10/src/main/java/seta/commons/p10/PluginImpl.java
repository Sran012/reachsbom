package seta.commons.p10;

import seta.spi.Plugin;

public final class PluginImpl implements Plugin {
    @Override
    public void run() {
        new org.apache.commons.text.StringSubstitutor().replace("${x}");
    }
}
