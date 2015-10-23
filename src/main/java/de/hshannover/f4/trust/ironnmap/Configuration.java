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
 * Website: http://trust.f4.hs-hannover.de/
 * 
 * This file is part of ironnmap, version 0.0.1, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2015 Trust@HsH
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

import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.hshannover.f4.trust.ironcommon.properties.Properties;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;

/**
 * This class loads the configuration file from the file system and provides a set of constants and a getter method to
 * access these values.
 * 
 * @author Marius Rohde
 * 
 */

public final class Configuration {

	private static final Logger LOGGER = LogManager.getLogger(Configuration.class.getName());

	/**
	 * The path to the configuration file.
	 */

	private static final String CONFIG_FILE = "/ironnmap.yml";

	private static Properties mProperties;

	// begin configuration parameter -------------------------------------------

	private static final String IFMAP_AUTH_METHOD = "ifmap.server.auth.method";
	private static final String IFMAP_URL_BASIC = "ifmap.server.url.basic";
	private static final String IFMAP_URL_CERT = "ifmap.server.url.cert";
	private static final String IFMAP_BASIC_USER = "ifmap.server.auth.user";
	private static final String IFMAP_BASIC_PASSWORD = "ifmap.server.auth.password";

	private static final String IFMAP_KEEPALIVE = "ifmap.client.keepalive";
	private static final String KEYSTORE_PATH = "ifmap.client.keystore.path";
	private static final String KEYSTORE_PASSWORD = "ifmap.client.keystore.password";
	private static final String NMAP_PATH = "ifmap.client.nmap.path";

	private static final String STRATEGIES_PACKAGE_PATH = "ifmap.client.publisher.publishstrategiespath";
	private static final String STRATEGIES_CLASSNAMES_FILENAME = "ifmap.client.publisher.publishstrategies";

	private static final String SUBSCRIBER_SUBSCRIPTIONROOT = "ifmap.client.subscriber.subscriptionroot";
	private static final String SUBSCRIBER_STRATEGIES_PACKAGE_PATH = "ifmap.client.subscriber.subscriberstrategiespath";
	private static final String SUBSCRIBER_STRATEGIES_CLASSNAMES_FILENAME = "ifmap.client.subscriber."
			+ "subscriberstrategies";

	// end configuration parameter ---------------------------------------------

	/**
	 * Death constructor for code convention -> final class because utility class
	 */
	private Configuration() {
	}

	/**
	 * Loads the configuration file. Every time this method is called the file is read again.
	 * 
	 * @throws PropertyException
	 *             To signalise a failure while opening to calling classes
	 * 
	 */
	public static void init() throws PropertyException {
		LOGGER.info("reading " + CONFIG_FILE + " ...");
		String config = Configuration.class.getResource(CONFIG_FILE).getPath();
		mProperties = new Properties(config);
	}

	/**
	 * Getter for the request Strategies classname map.
	 * 
	 * @return the set of classnames for request strategies
	 * @throws PropertyException
	 *             what the name says
	 */
	@SuppressWarnings("unchecked")
	public static Set<Entry<String, Object>> getRequestStrategiesClassnameMap() throws PropertyException {

		return ((Map<String, Object>) mProperties.getValue(STRATEGIES_CLASSNAMES_FILENAME)).entrySet();
	}

	/**
	 * Getter for the subscriber strategies classname map.
	 * 
	 * @return the set of classnames for subscriber strategies
	 * @throws PropertyException
	 *             what the name says
	 */
	@SuppressWarnings("unchecked")
	public static Set<Entry<String, Object>> getSubscriberStrategiesClassnameMap() throws PropertyException {

		return ((Map<String, Object>) mProperties.getValue(SUBSCRIBER_STRATEGIES_CLASSNAMES_FILENAME)).entrySet();
	}

	/**
	 * Getter for the ifmapAuthMethod property.
	 * 
	 * @return property string
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String ifmapAuthMethod() throws PropertyException {
		return mProperties.getString(IFMAP_AUTH_METHOD);

	}

	/**
	 * Getter for the ifmapUrlBasic property.
	 * 
	 * @return property string
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String ifmapUrlBasic() throws PropertyException {
		return mProperties.getString(IFMAP_URL_BASIC);
	}

	/**
	 * Getter for the ifmapUrlCert property.
	 * 
	 * @return property string
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String ifmapUrlCert() throws PropertyException {
		return mProperties.getString(IFMAP_URL_CERT);
	}

	/**
	 * Getter for the ifmapBasicUser property.
	 * 
	 * @return property string
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String ifmapBasicUser() throws PropertyException {
		return mProperties.getString(IFMAP_BASIC_USER);
	}

	/**
	 * Getter for the ifmapBasicPassword property.
	 * 
	 * @return property string
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String ifmapBasicPassword() throws PropertyException {
		return mProperties.getString(IFMAP_BASIC_PASSWORD);
	}

	/**
	 * Getter for the keyStorePath property.
	 * 
	 * @return property string
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String keyStorePath() throws PropertyException {
		return mProperties.getString(KEYSTORE_PATH);
	}

	/**
	 * Getter for the keyStorePassword property.
	 * 
	 * @return property string
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String keyStorePassword() throws PropertyException {
		return mProperties.getString(KEYSTORE_PASSWORD);
	}

	/**
	 * Getter for the ifmapKeepalive property.
	 * 
	 * @return property integer
	 * @throws PropertyException
	 *             what the name says
	 */
	public static int ifmapKeepalive() throws PropertyException {
		return mProperties.getInt(IFMAP_KEEPALIVE);
	}

	/**
	 * Getter for the strategies package path property.
	 * 
	 * @return property path
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String strategiesPackagePath() throws PropertyException {
		return mProperties.getString(STRATEGIES_PACKAGE_PATH);
	}

	/**
	 * Getter for the subscriber pdp.
	 * 
	 * @return property pdp
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String subscriberSubscriptionRoot() throws PropertyException {
		return mProperties.getString(SUBSCRIBER_SUBSCRIPTIONROOT);
	}

	/**
	 * Getter for the subscriber strategies package path property.
	 * 
	 * @return property path
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String subscriberStrategiesPackagePath() throws PropertyException {
		return mProperties.getString(SUBSCRIBER_STRATEGIES_PACKAGE_PATH);
	}

	/**
	 * Getter for the nmapPath property.
	 * 
	 * @return property string
	 * @throws PropertyException
	 *             what the name says
	 */
	public static String nmapPath() throws PropertyException {
		return mProperties.getString(NMAP_PATH);
	}

}
