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
import org.w3c.dom.Document;

import de.hshannover.f4.trust.ifmapj.IfmapJ;
import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.messages.MetadataLifetime;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ifmapj.metadata.Cardinality;
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

	public static final String IRONNMAP_SIMU_METADATA_NS_URI = "http://simu-project.de/XMLSchema/1";
	public static final String IRONNMAP_SIMU_METADATA_NS_PREFIX = "simu";

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
			publishHostDiscover(ssrc, nmapResult);
		}
	}

	public void publishHostDiscover(SSRC ssrc, NMapRun nmapResult) {

		try {
			String thisDevice = "nmap_"
					+ InetAddress.getLocalHost().getHostName();
			Identifier dev = Identifiers.createDev(thisDevice);

			for (Host host : nmapResult.getHosts()) {

				ArrayList<Identifier> ips = new ArrayList<Identifier>();
				Identifier mac = null;

				for (Address adr : host.getAddresses()) {
					if (adr.getAddrtype().equals("ipv4")) {
						Identifier ipv4 = Identifiers.createIp4(adr.getAddr());
						ips.add(ipv4);
						publishDiscover(ssrc, dev, ipv4);
						publishHopCount(ssrc, dev, ipv4,
								Long.toString(host.getDistance().getValue()));
						for (Port port : host.getPorts().getPorts()) {
							String extendedIdentifierXml = "<simu:service "
									+ "administrative-domain=\""+ ipv4 +"\" "
									+ "name=\""+host.getHostnames().getHostname()+"\" "
									+ "type=\""+port.getService().getName()+"\" "
									+ "port=\""+port.getPortId()+"\" "
									+ "protocol=\""+port.getProtocol()+"\" "
									+ "xmlns:simu=\""+IRONNMAP_SIMU_METADATA_NS_URI+"\" "
									+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
									+ "xsi:schemaLocation=\"http://www.example.com/extended-identifiers example-identifiers-2.1v1.xsd\" "
									+ "/>";
							Identifier extIdentService = Identifiers.createExtendedIdentity(extendedIdentifierXml);
							publishServiceIp(ssrc, extIdentService, ipv4);
							publishServiceDiscoBy(ssrc, extIdentService, dev);
						}
					} else if (adr.getAddrtype().equals("ipv6")) {
						Identifier ipv6 = Identifiers.createIp6(adr.getAddr()
								.toLowerCase());
						ips.add(ipv6);
						publishDiscover(ssrc, dev, ipv6);
						publishHopCount(ssrc, dev, ipv6,
								Long.toString(host.getDistance().getValue()));
						for (Port port : host.getPorts().getPorts()) {
							String extendedIdentifierXml = "<simu:service "
									+ "administrative-domain=\""+ ipv6 +"\" "
									+ "name=\""+host.getHostnames().getHostname()+"\" "
									+ "type=\""+port.getService().getName()+"\" "
									+ "port=\""+port.getPortId()+"\" "
									+ "protocol=\""+port.getProtocol()+"\" "
									+ "xmlns:simu=\""+IRONNMAP_SIMU_METADATA_NS_URI+"\" "
									+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
									+ "xsi:schemaLocation=\"http://www.example.com/extended-identifiers example-identifiers-2.1v1.xsd\" "
									+ "/>";
							Identifier extIdentService = Identifiers.createExtendedIdentity(extendedIdentifierXml);
							publishServiceIp(ssrc, extIdentService, ipv6);
							publishServiceDiscoBy(ssrc, extIdentService, dev);
						}
					} else if (adr.getAddrtype().equals("mac")) {
						mac = Identifiers
								.createMac(adr.getAddr().toLowerCase());
						publishDiscover(ssrc, dev, mac);
					}
				}
				for (Identifier ip : ips) {
					publishIpMac(ssrc, ip, mac);
				}
				if (mac != null) {
					String manufacturer = "";
					String model = "";
					String os = "";
					String osVersion = "";
					String deviceType = "";
					if (host.getOs() != null) {
						manufacturer = host.getOs().getOsClasses().get(0)
								.getVendor();
						os = host.getOs().getOsMatches().get(0).getName();
						osVersion = host.getOs().getOsMatches().get(0)
								.getName();
						deviceType = host.getOs().getOsClasses().get(0)
								.getType();
					}
					String discoveredTime = nmapResult.getRunStats()
							.getFinished().getTimestr();
					String discovererId = ssrc.getPublisherId();
					String discoveryMethod = "nmap";
					publishDevChar(ssrc, dev, mac, manufacturer, model, os,
							osVersion, deviceType, discoveredTime,
							discovererId, discoveryMethod);
				}

			}

		} catch (UnknownHostException e) {
			LOGGER.severe("Error lookup hostname: " + e);
		} catch (MarshalException e) {
			LOGGER.severe("Error building extended identifier from xml file: "
					+ e);
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

	private void publishDevChar(SSRC ssrc, Identifier ident1,
			Identifier ident2, String manufacturer, String model, String os,
			String osVersion, String deviceType, String discoveredTime,
			String discovererId, String discoveryMethod) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory()
					.createDevChar(manufacturer, model, os, osVersion,
							deviceType, discoveredTime, discovererId,
							discoveryMethod);
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1,
					ident2, docMeta, MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	private void publishHopCount(SSRC ssrc, Identifier ident1,
			Identifier ident2, String hopCount) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().create(
					"hop-count", IRONNMAP_SIMU_METADATA_NS_PREFIX,
					IRONNMAP_SIMU_METADATA_NS_URI, Cardinality.singleValue,
					"value", hopCount);
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1,
					ident2, docMeta, MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	private void publishServiceIp(SSRC ssrc, Identifier ident1,
			Identifier ident2) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().create(
					"service-ip", IRONNMAP_SIMU_METADATA_NS_PREFIX,
					IRONNMAP_SIMU_METADATA_NS_URI, Cardinality.singleValue);
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1,
					ident2, docMeta, MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	private void publishServiceDiscoBy(SSRC ssrc, Identifier ident1,
			Identifier ident2) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().create(
					"service-discovered-by", IRONNMAP_SIMU_METADATA_NS_PREFIX,
					IRONNMAP_SIMU_METADATA_NS_URI, Cardinality.singleValue);
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
