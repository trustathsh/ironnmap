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

import java.util.Timer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;
import net.sourceforge.argparse4j.inf.Subparsers;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.exception.InitializationException;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;
import de.hshannover.f4.trust.ironnmap.publisher.StrategyChainBuilder;
import de.hshannover.f4.trust.ironnmap.publisher.strategies.ScanSingleTime;
import de.hshannover.f4.trust.ironnmap.subscriber.SubscriberStrategyChainBuilder;
import de.hshannover.f4.trust.ironnmap.subscriber.SubscriberThread;
import de.hshannover.f4.trust.ironnmap.utilities.IfMap;
import de.hshannover.f4.trust.ironnmap.utilities.SsrcKeepaliveThread;

/**
 * This class starts the application It creates the threads for publishing, keepalives. It setups logging too
 * 
 * @author Marius Rohde
 * 
 */

public final class Ironnmap {

	private static final Logger LOGGER = LogManager.getLogger(Ironnmap.class.getName());

	/**
	 * Death constructor for code convention -> final class because utility class
	 */
	private Ironnmap() {
	}

	/**
	 * Main method ... start me here!!!
	 * 
	 */
	public static void main(String[] args) {

		try {
			Configuration.init();

			// singleTime -inc 192.168.1.14 flags -- -sV -PN -O
			Namespace ns = parseArgs(args);

			StrategyChainBuilder.init(Configuration.getRequestStrategiesClassnameMap(),
					Configuration.strategiesPackagePath());

			SubscriberStrategyChainBuilder.init(Configuration.getSubscriberStrategiesClassnameMap(),
					Configuration.subscriberStrategiesPackagePath());

			IfMap.initSsrc(Configuration.ifmapAuthMethod(), Configuration.ifmapUrlBasic(),
					Configuration.ifmapUrlCert(), Configuration.ifmapBasicUser(), Configuration.ifmapBasicPassword(),
					Configuration.keyStorePath(), Configuration.keyStorePassword());

			IfMap.getSsrc().newSession();

			if (ns.getString("purging").equals("purge")) {
				IfMap.getSsrc().purgePublisher();
			}

			Timer timerA = new Timer();
			timerA.schedule(new SsrcKeepaliveThread(), 1000, Configuration.ifmapKeepalive() * 1000 * 60);

			if (ns.getString("execution").equals("singleTime")) {
				String flagsWithMinus = "";
				for (Object flag : ns.getList("flags").subList(1, ns.getList("flags").size()))
					flagsWithMinus += "" + flag.toString() + " ";
				try {
					ScanSingleTime oneTime = new ScanSingleTime(ns.getString("include"), ns.getString("exclude"),
							flagsWithMinus);
					oneTime.publishNmapStrategy(IfMap.getSsrc());
				} catch (PropertyException e) {
					LOGGER.fatal("Error initializing the ScanSingleTime strategy");
				}
				timerA.cancel();
			} else {
				new SubscriberThread().start();
				LOGGER.info("Subscriber startet.");
				// TODO super clean shutdown
			}

		} catch (InitializationException e1) {
			LOGGER.fatal("Error setting up the ssrc channel... System can not start!");
		} catch (IfmapErrorResult e1) {
			LOGGER.fatal("Error setting up the ssrc channel session... System can not start!");
		} catch (IfmapException e1) {
			LOGGER.fatal("Error setting up the ssrc channel session... System can not start!");
		} catch (PropertyException e1) {
			LOGGER.fatal("Error setting up the configuration... System can not start!");
		}

	}

	/**
	 * parse Arguments
	 * 
	 * @return Namespace Object with parameters
	 */
	public static Namespace parseArgs(String[] args) {

		ArgumentParser parser = ArgumentParsers.newArgumentParser("use of ironnmap").defaultHelp(true)
				.description("publish nmap informations about hosts");
		parser.addArgument("-purgePublisher").dest("purging").choices("purge", "nopurge").setDefault("nopurge")
				.help("purge previous published data");
		parser.setDefault("execution", "multiTime");
		Subparsers subparsers = parser.addSubparsers().dest("execution").help("sub-command help");
		Subparser parserA = subparsers.addParser("singleTime").help("single commandline execution");
		Subparser parserB = subparsers.addParser("multiTime").help("subscribing for request for investigation");
		parserB.defaultHelp(true);

		parserA.addArgument("-inc").dest("include").required(true).help("include Hosts for scan");
		parserA.addArgument("-exc").dest("exclude").help("exclude Hosts for scan");
		parserA.addArgument("flags").dest("flags").required(true).nargs("*")
				.help("use -- before nmap flags to use - with flags");
		Namespace ns = null;
		try {
			if (args.length == 0) {
				String[] args1 = new String[1];
				args1[0] = "multiTime";
				args = args1;
			}
			ns = parser.parseArgs(args);
		} catch (ArgumentParserException e) {
			parser.handleError(e);
			// LOGGER.severe("Error parsing the commandline input... System can not start!");
			System.exit(1);
		}
		return ns;
	}

}
