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
import org.nmap4j.data.host.ports.Port;
import org.nmap4j.data.nmaprun.Host;

import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;
import de.hshannover.f4.trust.ironnmap.publisher.PublishNmapStrategy;

/**
 * This class is the implementation to request Nmap one time for all informations specified by flags for a range of
 * hosts
 * 
 * 
 * @author Marius Rohde
 * 
 */

public class ScanSingleTime extends PublishNmapStrategy {

	private static final Logger LOGGER = Logger.getLogger(ScanSingleTime.class.getName());

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
	public ScanSingleTime(String ipInclude, String ipExclude, String nmapFlags) throws PropertyException {
		super();
		mIpInclude = ipInclude;
		mIpExclude = ipExclude;
		mNmapFlags = nmapFlags;
	}

	@Override
	public void publishNmapStrategy(SSRC ssrc) {

		NMapRun nmapResult = getNmapXmlString(mIpInclude, mIpExclude, mNmapFlags);
		if (nmapResult != null) {
			publishHostDiscover(ssrc, nmapResult);
		}
	}

	/**
	 * Helper to publish all informations about hosts
	 * 
	 * @param SSRC
	 *            ssrc
	 * @param NMapRun
	 *            nmap result
	 */
	private void publishHostDiscover(SSRC ssrc, NMapRun nmapResult) {

		try {
			String thisDevice = "nmap_" + InetAddress.getLocalHost().getHostName();
			Identifier dev = Identifiers.createDev(thisDevice);

			for (Host host : nmapResult.getHosts()) {

				ArrayList<Identifier> ips = new ArrayList<Identifier>();
				Identifier mac = null;

				// check every address of host for type mac ipv4 or ipv6
				for (Address adr : host.getAddresses()) {
					// ipv4
					if (adr.getAddrtype().equals("ipv4")) {
						Identifier ipv4 = Identifiers.createIp4(adr.getAddr());
						ips.add(ipv4);
						publishDiscover(ssrc, dev, ipv4);
						if (host.getDistance() != null) {
							publishHopCount(ssrc, dev, ipv4, Long.toString(host.getDistance().getValue()));
						}
						// ports and services
						for (Port port : host.getPorts().getPorts()) {
							Identifier extIdentService = Identifiers.createExtendedIdentity(createSimuServiceXml(ipv4,
									host, port));
							publishServiceIp(ssrc, extIdentService, ipv4);
							publishServiceDiscoBy(ssrc, extIdentService, dev);
							String xmlSimuImpl = createSimuImplementationXml(ipv4, port);
							if (xmlSimuImpl != null) {
								Identifier extIdentImplementation = Identifiers.createExtendedIdentity(xmlSimuImpl);
								publishServiceImplementation(ssrc, extIdentService, extIdentImplementation);
							}
						}
						// publish Operating System
						String xmlSimuOs = createSimuOsXml(ipv4, host);
						if (xmlSimuOs != null) {
							Identifier extIdentService = Identifiers.createExtendedIdentity(xmlSimuOs);
							publishServiceIp(ssrc, extIdentService, ipv4);
							publishServiceDiscoBy(ssrc, extIdentService, dev);
							String xmlSimuImpl = createOsSimuImplementationXml(ipv4, host);
							if (xmlSimuImpl != null) {
								Identifier extIdentImplementation = Identifiers.createExtendedIdentity(xmlSimuImpl);
								publishServiceImplementation(ssrc, extIdentService, extIdentImplementation);
							}
						}
						// ipv6
					} else if (adr.getAddrtype().equals("ipv6")) {
						Identifier ipv6 = Identifiers.createIp6(adr.getAddr().toLowerCase());
						ips.add(ipv6);
						publishDiscover(ssrc, dev, ipv6);
						if (host.getDistance() != null) {
							publishHopCount(ssrc, dev, ipv6, Long.toString(host.getDistance().getValue()));
						}
						// ports and services
						for (Port port : host.getPorts().getPorts()) {
							Identifier extIdentService = Identifiers.createExtendedIdentity(createSimuServiceXml(ipv6,
									host, port));
							publishServiceIp(ssrc, extIdentService, ipv6);
							publishServiceDiscoBy(ssrc, extIdentService, dev);
							String xmlSimuImpl = createSimuImplementationXml(ipv6, port);
							if (xmlSimuImpl != null) {
								Identifier extIdentImplementation = Identifiers.createExtendedIdentity(xmlSimuImpl);
								publishServiceImplementation(ssrc, extIdentService, extIdentImplementation);
							}
						}
						// publish Operating System
						String xmlSimuOs = createSimuOsXml(ipv6, host);
						if (xmlSimuOs != null) {
							Identifier extIdentService = Identifiers.createExtendedIdentity(xmlSimuOs);
							publishServiceIp(ssrc, extIdentService, ipv6);
							publishServiceDiscoBy(ssrc, extIdentService, dev);
							String xmlSimuImpl = createOsSimuImplementationXml(ipv6, host);
							if (xmlSimuImpl != null) {
								Identifier extIdentImplementation = Identifiers.createExtendedIdentity(xmlSimuImpl);
								publishServiceImplementation(ssrc, extIdentService, extIdentImplementation);
							}
						}
						// mac
					} else if (adr.getAddrtype().equals("mac")) {
						mac = Identifiers.createMac(adr.getAddr().toLowerCase());
						publishDiscover(ssrc, dev, mac);
					}
				}
				// everything for publishing mac data
				// only one mac per host can occur
				for (Identifier ip : ips) {
					publishIpMac(ssrc, ip, mac);
				}
				if (mac != null) {
					String manufacturer = "";
					String model = "";
					String os = "";
					String osVersion = "";
					String deviceType = "";
					// publish Operating System on device characteristics
					if (host.getOs() != null) {
						manufacturer = host.getOs().getOsClasses().get(0).getVendor();
						os = host.getOs().getOsMatches().get(0).getName();
						osVersion = host.getOs().getOsMatches().get(0).getName();
						deviceType = host.getOs().getOsClasses().get(0).getType();
					}
					String discoveredTime = nmapResult.getRunStats().getFinished().getTimestr();
					String discovererId = ssrc.getPublisherId();
					String discoveryMethod = "nmap";
					publishDevChar(ssrc, dev, mac, manufacturer, model, os, osVersion, deviceType, discoveredTime,
							discovererId, discoveryMethod);
				}

			}
			LOGGER.info("Nmap data published");
		} catch (UnknownHostException e) {
			LOGGER.severe("Error lookup hostname: " + e);
		} catch (MarshalException e) {
			LOGGER.severe("Error building extended identifier from xml file: " + e);
		}
	}
}
