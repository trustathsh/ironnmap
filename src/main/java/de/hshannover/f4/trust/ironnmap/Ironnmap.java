/*
 * #%L
 * =====================================================
 *   _____                _     ____  _   _       _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \| | | | ___ | | | |
 *    | | | '__| | | / __| __|/ / _` | |_| |/ __|| |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _  |\__ \|  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_| |_||___/|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Hochschule Hannover
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.f4.hs-hannover.de
 * 
 * This file is part of ironnmap, version 0.0.1, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2015 - 2015 Trust@HsH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

package de.hshannover.f4.trust.ironnmap;

import java.io.IOException;
import java.io.InputStream;
import java.util.Timer;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.exception.InitializationException;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;
import de.hshannover.f4.trust.ironnmap.publisher.StrategyChainBuilder;
import de.hshannover.f4.trust.ironnmap.utilities.IfMap;
import de.hshannover.f4.trust.ironnmap.utilities.SsrcKeepaliveThread;

/**
 * This class starts the application It creates the threads for publishing,
 * keepalives. It setups logging too
 * 
 * @author Marius Rohde
 * 
 */

public final class Ironnmap {

	private static final Logger LOGGER = Logger.getLogger(Ironnmap.class.getName());

	private static final String LOGGING_CONFIG_FILE = "/logging.properties";

	/**
	 * Death constructor for code convention -> final class because utility
	 * class
	 */
	private Ironnmap() {
	}

	public static void main(String[] args) {

		setupLogging();

		try {
			Configuration.init();

			StrategyChainBuilder.init(Configuration.getRequestStrategiesClassnameMap(),
					Configuration.strategiesPackagePath());

			IfMap.initSsrc(Configuration.ifmapAuthMethod(), Configuration.ifmapUrlBasic(),
					Configuration.ifmapUrlCert(), Configuration.ifmapBasicUser(), Configuration.ifmapBasicPassword(),
					Configuration.keyStorePath(), Configuration.keyStorePassword());

			IfMap.getSsrc().newSession();
			IfMap.getSsrc().purgePublisher();

			Timer timerA = new Timer();
			timerA.schedule(new SsrcKeepaliveThread(), 1000, Configuration.ifmapKeepalive() * 1000 * 60);

		} catch (InitializationException e1) {
			LOGGER.severe("Error setting up the ssrc channel... System can not start!");
		} catch (IfmapErrorResult e1) {
			LOGGER.severe("Error setting up the ssrc channel session... System can not start!");
		} catch (IfmapException e1) {
			LOGGER.severe("Error setting up the ssrc channel session... System can not start!");
		} catch (PropertyException e1) {
			LOGGER.severe("Error setting up the configuration... System can not start!");
		}
	}

	/**
	 * Initialize logging
	 * 
	 */

	public static void setupLogging() {

		InputStream in = Ironnmap.class.getResourceAsStream(LOGGING_CONFIG_FILE);

		try {
			LogManager.getLogManager().readConfiguration(in);
		} catch (Exception e) {
			Handler handler = new ConsoleHandler();
			handler.setLevel(Level.ALL);

			Logger.getLogger("").addHandler(handler);
			Logger.getLogger("").setLevel(Level.INFO);

			LOGGER.warning("could not read " + LOGGING_CONFIG_FILE + ", using defaults");

		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					LOGGER.warning("could not close log config inputstream: " + e);
				}
			}
		}
	}

}
