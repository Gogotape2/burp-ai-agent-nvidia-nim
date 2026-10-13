package com.six2dez.burp.aiagent.spi

/*
 * Test-only SPIs for PluginsSelectionTest. They are NOT production extension points: their services
 * files live in src/test/resources, so no JAR ever carries them and the production SPI catalog stays
 * exactly what the two builds ship.
 */

/** An SPI with no provider registered anywhere. */
interface UnregisteredProbe

/** An SPI with exactly one provider (src/test/resources/META-INF/services). */
interface SingleProbe

/** An SPI with two providers (src/test/resources/META-INF/services). */
interface DoubleProbe

class SingleProbeImpl : SingleProbe

class DoubleProbeAlpha : DoubleProbe

class DoubleProbeBeta : DoubleProbe
