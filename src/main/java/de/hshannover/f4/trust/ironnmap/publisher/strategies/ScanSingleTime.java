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
package de.hshannover.f4.trust.ironnmap.publisher.strategies;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.logging.Logger;

import org.nmap4j.data.NMapRun;
import org.nmap4j.data.host.Address;
import org.nmap4j.data.nmaprun.Host;
import org.w3c.dom.Document;

import de.hshannover.f4.trust.ifmapj.IfmapJ;
import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.messages.MetadataLifetime;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;
import de.hshannover.f4.trust.ironnmap.publisher.PublishNmapStrategy;

/**
 * This class is the implementation to request Nmap one time for all
 * informations specified by flags for a range of hosts
 * 
 * 
 * @author Marius Rohde
 * 
 */

public class ScanSingleTime extends PublishNmapStrategy {

	private static final Logger LOGGER = Logger.getLogger(ScanSingleTime.class
			.getName());

	String mIpInclude;
	String mIpExclude;
	String mNmapFlags;

	/**
	 * A Constructor to directly instantiate a single time scan
	 * 
	 * @param ipInclude
	 *            Hosts to scan
	 * @param ipExclude
	 *            Hosts not to scan
	 * @param nmapFlags
	 *            flags how to scan
	 * 
	 * @throws PropertyException
	 *             Configuration read
	 */
	public ScanSingleTime(String ipInclude, String ipExclude, String nmapFlags)
			throws PropertyException {
		super();
		mIpInclude = ipInclude;
		mIpExclude = ipExclude;
		mNmapFlags = nmapFlags;
	}

	@Override
	public void publishNmapStrategy(SSRC ssrc) {

		NMapRun nmapResult = getNmapXmlString(mIpInclude, mIpExclude,
				mNmapFlags);
		if (nmapResult != null) {
			publishAdressDiscover(ssrc, nmapResult);
		}
	}

	public void publishAdressDiscover(SSRC ssrc, NMapRun nmapResult) {

		try {
			String thisDevice = "nmap_"
					+ InetAddress.getLocalHost().getHostName();
			Identifier ident1 = Identifiers.createDev(thisDevice);

			for (Host host : nmapResult.getHosts()) {

				ArrayList<Identifier> ips = new ArrayList<Identifier>();
				Identifier mac = null;

				for (Address adr : host.getAddresses()) {
					if (adr.getAddrtype().equals("ipv4")) {
						Identifier ident2 = Identifiers
								.createIp4(adr.getAddr());
						ips.add(ident2);
						publishDiscover(ssrc, ident1, ident2);
					} else if (adr.getAddrtype().equals("ipv6")) {
						Identifier ident2 = Identifiers.createIp6(adr.getAddr()
								.toLowerCase());
						ips.add(ident2);
						publishDiscover(ssrc, ident1, ident2);
					} else if (adr.getAddrtype().equals("mac")) {
						Identifier ident2 = Identifiers.createMac(adr.getAddr()
								.toLowerCase());
						mac = ident2;
						publishDiscover(ssrc, ident1, ident2);
					}
				}
				for (Identifier ip : ips) {
					publishIpMac(ssrc, ip, mac);
				}
			}

		} catch (UnknownHostException e) {
			LOGGER.severe("Error lookup hostname: " + e);
		}
	}

	private void publishIpMac(SSRC ssrc, Identifier ident1, Identifier ident2) {

		try {
			if (ident1 != null && ident2 != null) {
				Document docMeta = IfmapJ.createStandardMetadataFactory()
						.createIpMac();
				PublishUpdate publishUpdate = Requests.createPublishUpdate(
						ident1, ident2, docMeta, MetadataLifetime.forever);
				ssrc.publish(Requests.createPublishReq(publishUpdate));
			}
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	private void publishDiscover(SSRC ssrc, Identifier ident1, Identifier ident2) {

		try {

			Document docMeta = IfmapJ.createStandardMetadataFactory()
					.createDiscoveredBy();
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1,
					ident2, docMeta, MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

}
