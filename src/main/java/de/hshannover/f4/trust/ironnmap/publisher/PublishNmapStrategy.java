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

package de.hshannover.f4.trust.ironnmap.publisher;

import java.util.logging.Logger;

import org.nmap4j.Nmap4j;
import org.nmap4j.core.nmap.NMapExecutionException;
import org.nmap4j.core.nmap.NMapInitializationException;
import org.nmap4j.data.NMapRun;

import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;
import de.hshannover.f4.trust.ironnmap.Configuration;

/**
 * This abstract class is an abstract represent of the Implementation of the
 * different publisher strategies
 * 
 * 
 * @author Marius Rohde
 * 
 */

public abstract class PublishNmapStrategy {

	private static final Logger LOGGER = Logger
			.getLogger(PublishNmapStrategy.class.getName());

	private Nmap4j mNmap4j;

	/**
	 * Constructor to initialize nMap4j for the PublishNmapStrategy
	 * 
	 * @throws PropertyException
	 *             Configuration read
	 */
	protected PublishNmapStrategy() throws PropertyException {
		mNmap4j = new Nmap4j(Configuration.nmapPath());
	}

	/**
	 * Abstract methode to publish the the informations. Has to be implemented
	 * by the different subclass strategies
	 */
	public abstract void publishNmapStrategy(SSRC ssrc);

	/**
	 * Helper method to get the xml String of nmap output
	 * 
	 * @param ipInclude
	 *            included Hosts ip range
	 * @param ipExclude
	 *            excluded Hosts ip range
	 * @param nmapFlags
	 *            Arraylist of nmap flags for scanning hosts
	 * @return Nmap XML prent node nmaprun
	 */
	public NMapRun getNmapXmlString(String ipInclude, String ipExclude,
			String nmapFlags) {

		NMapRun nmapRun = null;

		mNmap4j.includeHosts(ipInclude);
		if (ipExclude != null) {
			if (!ipExclude.equals("")) {
				mNmap4j.excludeHosts(ipExclude);
			}
		}
		mNmap4j.addFlags(nmapFlags);

		try {
			mNmap4j.execute();
		} catch (NMapInitializationException e) {
			LOGGER.severe("Error initializing NMAP: " + e);
		} catch (NMapExecutionException e) {
			LOGGER.severe("Error executing NMAP: " + e);
		}

		if (!mNmap4j.hasError()) {
			nmapRun = mNmap4j.getResult();
			System.out.println(mNmap4j.getOutput());
		} else {
			LOGGER.severe(mNmap4j.getExecutionResults().getErrors());
		}

		return nmapRun;
	}

}
