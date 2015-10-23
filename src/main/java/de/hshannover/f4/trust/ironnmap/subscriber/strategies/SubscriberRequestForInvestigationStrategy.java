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

package de.hshannover.f4.trust.ironnmap.subscriber.strategies;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.IpAddress;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;
import de.hshannover.f4.trust.ironnmap.publisher.strategies.ScanSingleTime;
import de.hshannover.f4.trust.ironnmap.subscriber.SubscriberNmapStrategy;

/**
 * This class is the implementation to act on requestForInvestigation Meta data. After the occurrence of the
 * reqForInvestigation, the client scans the ip or mac with Nmap and publishes the os scan data.
 * The request-for-investigation metadata is not checked for its qualifier-value.
 *
 * @author Marius Rohde
 * @author Bastian Hellmann
 *
 */

public class SubscriberRequestForInvestigationStrategy extends SubscriberNmapStrategy {

	private static final Logger LOGGER =
			LogManager.getLogger(SubscriberRequestForInvestigationStrategy.class.getName());

	private static final String SUBSCRIBERNAME = "nmap_reqForInv";

	private static final String SUBSCRIBERFILTER = "meta:request-for-investigation";

	@Override
	protected String getSubscriberName() {
		return SUBSCRIBERNAME;
	}

	@Override
	protected String getSubscriberFilter() {
		return SUBSCRIBERFILTER;
	}

	@Override
	protected void scanWithStrategy(SSRC ssrc, Identifier ipIdent) {
		try {
			if (ipIdent instanceof IpAddress) {
				IpAddress ip = (IpAddress) ipIdent;

				ScanSingleTime scan = new ScanSingleTime(ip.getValue(), "", "-sV -PN -O");
				scan.publishNmapStrategy(ssrc);

			}
		} catch (PropertyException e) {
			LOGGER.fatal("Couldn't read property");
		}
	}

}
