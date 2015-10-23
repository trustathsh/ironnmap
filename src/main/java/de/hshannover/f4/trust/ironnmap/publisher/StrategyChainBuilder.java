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
package de.hshannover.f4.trust.ironnmap.publisher;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class initialize the strategy chain to get the strategies for publishing nmap data. The config file defines
 * which strategies will be load by reflection Objects
 * 
 * 
 * @author Marius Rohde
 * 
 */

public final class StrategyChainBuilder {

	private static final Logger LOGGER = LogManager.getLogger(StrategyChainBuilder.class.getName());

	/**
	 * the List/Chain with the different strategy objects
	 */
	private static ArrayList<PublishNmapStrategy> strategyChain;

	/**
	 * Death constructor for code convention -> final class because utility class
	 * 
	 */
	private StrategyChainBuilder() {
	}

	/**
	 * The init method initiate the strategy chain and looks for the classes in packagepath
	 */

	public static void init(Set<Entry<String, Object>> strategieNames, String packagePath) {

		LOGGER.info("looking for classes in package " + packagePath);

		PublishNmapStrategy publisherStrategy;
		Iterator<Entry<String, Object>> iteClassnames = strategieNames.iterator();
		strategyChain = new ArrayList<PublishNmapStrategy>();

		while (iteClassnames.hasNext()) {

			Entry<String, Object> classname = iteClassnames.next();
			LOGGER.info("found classString in Properties: " + classname.getKey().toString());

			if (classname.getValue().toString().equals("enabled")) {

				publisherStrategy = createNewStrategie(packagePath + classname.getKey().toString());
				if (publisherStrategy != null) {
					strategyChain.add(publisherStrategy);
				}
			} else {
				LOGGER.warn("Class is not enabled!: " + classname.getKey().toString());
			}
		}
	}

	/**
	 * This helper method creates a new StrategieObject
	 * 
	 * @param className
	 * @return Strategy object
	 */

	private static PublishNmapStrategy createNewStrategie(String className) {

		PublishNmapStrategy strategy = null;

		try {
			Class<?> cl = Class.forName(className);
			LOGGER.info(cl.toString() + " instantiated");
			if (cl.getSuperclass() == PublishNmapStrategy.class) {
				strategy = (PublishNmapStrategy) cl.newInstance();
			}

		} catch (ClassNotFoundException e) {
			LOGGER.fatal("ClassNotFound");
		} catch (InstantiationException e) {
			LOGGER.fatal("InstantiationException");
		} catch (IllegalAccessException e) {
			LOGGER.fatal("IllegalAccessException");
		}

		return strategy;
	}

	/**
	 * The Size of the Chain
	 * 
	 * @return the size
	 */

	public static int getSize() {

		return strategyChain.size();
	}

	/**
	 * This method delivers a StrategyObject stored in the chain
	 * 
	 * @param index
	 *            the index of the element
	 * @return an Element
	 */

	public static PublishNmapStrategy getElementAt(int index) {

		return strategyChain.get(index);
	}

}
