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
import org.nmap4j.data.host.ports.Port;
import org.nmap4j.data.nmaprun.Host;
import org.w3c.dom.Document;

import de.hshannover.f4.trust.ifmapj.IfmapJ;
import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.IpAddress;
import de.hshannover.f4.trust.ifmapj.messages.MetadataLifetime;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ifmapj.metadata.Cardinality;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;
import de.hshannover.f4.trust.ironnmap.Configuration;

/**
 * This abstract class is an abstract represent of the Implementation of the different publisher strategies
 * 
 * 
 * @author Marius Rohde
 * 
 */

public abstract class PublishNmapStrategy {

	protected static final String IRONNMAP_SIMU_METADATA_NS_URI = "http://simu-project.de/XMLSchema/1";
	protected static final String IRONNMAP_SIMU_METADATA_NS_PREFIX = "simu";

	private static final Logger LOGGER = Logger.getLogger(PublishNmapStrategy.class.getName());

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
	 * Abstract methode to publish the the informations. Has to be implemented by the different subclass strategies
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
	public NMapRun getNmapXmlString(String ipInclude, String ipExclude, String nmapFlags) {

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

	/**
	 * Helper method to publish ipMac Metadata
	 * 
	 * @param ssrc
	 *            ssrc
	 * @param ident1
	 *            ip
	 * @param ident2
	 *            mac
	 */
	protected void publishIpMac(SSRC ssrc, Identifier ident1, Identifier ident2) {

		try {
			if (ident1 != null && ident2 != null) {
				Document docMeta = IfmapJ.createStandardMetadataFactory().createIpMac();
				PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1, ident2, docMeta,
						MetadataLifetime.forever);
				ssrc.publish(Requests.createPublishReq(publishUpdate));
			}
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	/**
	 * Helper method to publish dicoverd by Metadata
	 * 
	 * @param ssrc
	 *            ssrc
	 * @param ident1
	 *            device
	 * @param ident2
	 *            mac or ip
	 */
	protected void publishDiscover(SSRC ssrc, Identifier ident1, Identifier ident2) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().createDiscoveredBy();
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1, ident2, docMeta,
					MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	/**
	 * Helper method to publish device chracteristics
	 * 
	 * @param ssrc
	 *            ssrc
	 * @param ident1
	 *            device
	 * @param ident2
	 *            mac
	 * @param manufacturer
	 *            manufacturer
	 * @param model
	 *            model
	 * @param os
	 *            os
	 * @param osVersion
	 *            osVersion
	 * @param deviceType
	 *            deviceType
	 * @param discoveredTime
	 *            discoveredTime
	 * @param discovererId
	 *            discovererId
	 * @param discoveryMethod
	 *            discoveryMethod
	 */
	protected void publishDevChar(SSRC ssrc, Identifier ident1, Identifier ident2, String manufacturer, String model,
			String os, String osVersion, String deviceType, String discoveredTime, String discovererId,
			String discoveryMethod) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().createDevChar(manufacturer, model, os,
					osVersion, deviceType, discoveredTime, discovererId, discoveryMethod);
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1, ident2, docMeta,
					MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	/**
	 * Helper method to publish hopcount simu metadata
	 * 
	 * @param ssrc
	 *            ssrc
	 * @param ident1
	 *            device
	 * @param ident2
	 *            mac or ip
	 * @param hopCount
	 *            hopCount
	 */
	protected void publishHopCount(SSRC ssrc, Identifier ident1, Identifier ident2, String hopCount) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().create("hop-count",
					IRONNMAP_SIMU_METADATA_NS_PREFIX, IRONNMAP_SIMU_METADATA_NS_URI, Cardinality.singleValue, "value",
					hopCount);
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1, ident2, docMeta,
					MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	/**
	 * Helper method to publish hopcount simu metadata
	 * 
	 * @param ssrc
	 *            ssrc
	 * @param ident1
	 *            service
	 * @param ident2
	 *            ip
	 */
	protected void publishServiceIp(SSRC ssrc, Identifier ident1, Identifier ident2) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().create("service-ip",
					IRONNMAP_SIMU_METADATA_NS_PREFIX, IRONNMAP_SIMU_METADATA_NS_URI, Cardinality.singleValue);
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1, ident2, docMeta,
					MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	/**
	 * Helper method to publish service discovered by simu metadata
	 * 
	 * @param ssrc
	 *            ssrc
	 * @param ident1
	 *            service
	 * @param ident2
	 *            device
	 */
	protected void publishServiceDiscoBy(SSRC ssrc, Identifier ident1, Identifier ident2) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().create("service-discovered-by",
					IRONNMAP_SIMU_METADATA_NS_PREFIX, IRONNMAP_SIMU_METADATA_NS_URI, Cardinality.singleValue);
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1, ident2, docMeta,
					MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	/**
	 * Helper method to publish service implementation simu metadata
	 * 
	 * @param ssrc
	 *            ssrc
	 * @param ident1
	 *            service
	 * @param ident2
	 *            implementation
	 */
	protected void publishServiceImplementation(SSRC ssrc, Identifier ident1, Identifier ident2) {

		try {
			Document docMeta = IfmapJ.createStandardMetadataFactory().create("service-implementation",
					IRONNMAP_SIMU_METADATA_NS_PREFIX, IRONNMAP_SIMU_METADATA_NS_URI, Cardinality.singleValue);
			PublishUpdate publishUpdate = Requests.createPublishUpdate(ident1, ident2, docMeta,
					MetadataLifetime.forever);
			ssrc.publish(Requests.createPublishReq(publishUpdate));
		} catch (IfmapErrorResult e) {
			LOGGER.severe("Error publishing update data: " + e);
		} catch (IfmapException e) {
			LOGGER.severe("Error publishing update data: " + e);
		}

	}

	/**
	 * Helper method to create service xml string for simu service identifier
	 * 
	 * @param ip
	 *            ip
	 * @param host
	 *            current host
	 * @param port
	 *            current port
	 * @return xmlString
	 */
	protected String createSimuServiceXml(Identifier ip, Host host, Port port) {
		String extendedIdentifierXmlService = null;
		String name = "";
		String type = "";

		if (ip instanceof IpAddress) {
			if (host.getHostnames().getHostname().getName() != null) {
				name = host.getHostnames().getHostname().getName();
			}
			if (port.getService().getName() != null) {
				type = port.getService().getName();
			}

			extendedIdentifierXmlService = "<simu:service "
					+ "administrative-domain=\""
					+ ip
					+ "\" "
					+ "name=\""
					+ name
					+ "\" "
					+ "type=\""
					+ type
					+ "\" "
					+ "port=\""
					+ port.getPortId()
					+ "\" "
					+ "protocol=\""
					+ port.getProtocol()
					+ "\" "
					+ "xmlns:simu=\""
					+ IRONNMAP_SIMU_METADATA_NS_URI
					+ "\" "
					+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
					+ "xsi:schemaLocation=\"http://www.example.com/extended-identifiers example-identifiers-2.1v1.xsd\" "
					+ "/>";
		}
		return extendedIdentifierXmlService;
	}

	/**
	 * Helper method to create service(Operating System) xml string for simu service identifier
	 * 
	 * @param ip
	 *            ip
	 * @param host
	 *            current host
	 * @return xmlString
	 */
	protected String createSimuOsXml(Identifier ip, Host host) {
		String extendedIdentifierXmlService = null;
		String name = "";
		String type = "Operating System";

		if (ip instanceof IpAddress) {
			if (host.getHostnames().getHostname().getName() != null) {
				name = host.getHostnames().getHostname().getName();
			}

			extendedIdentifierXmlService = "<simu:service "
					+ "administrative-domain=\""
					+ ip
					+ "\" "
					+ "name=\""
					+ name
					+ "\" "
					+ "type=\""
					+ type
					+ "\" "
					+ "port=\""
					+ "\" "
					+ "protocol=\""
					+ "\" "
					+ "xmlns:simu=\""
					+ IRONNMAP_SIMU_METADATA_NS_URI
					+ "\" "
					+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
					+ "xsi:schemaLocation=\"http://www.example.com/extended-identifiers example-identifiers-2.1v1.xsd\" "
					+ "/>";
		}
		return extendedIdentifierXmlService;
	}

	/**
	 * Helper method to create implementation xml string for simu implementation identifier
	 * 
	 * @param ip
	 *            ip
	 * @param port
	 *            current port
	 * @return xmlString
	 */
	protected String createSimuImplementationXml(Identifier ip, Port port) {
		String extendedIdentifierXmlImplementation = null;
		String name = "";
		String version = "";
		String localVersion = "";
		String platform = "";

		if (ip instanceof IpAddress) {
			if (port.getService().getProduct() != null) {
				name = port.getService().getProduct();
			}
			if (port.getService().getVersion() != null) {
				version = port.getService().getVersion();
			}
			if (port.getService().getOsType() != null) {
				platform = port.getService().getOsType();
			}

			if (!(port.getService().getProduct() == null && port.getService().getVersion() == null && port
					.getService().getOsType() == null)) {
				extendedIdentifierXmlImplementation = "<simu:implementation "
						+ "administrative-domain=\""
						+ ip
						+ "\" "
						+ "name=\""
						+ name
						+ "\" "
						+ "version=\""
						+ version
						+ "\" "
						+ "local-version=\""
						+ localVersion
						+ "\" "
						+ "platform=\""
						+ platform
						+ "\" "
						+ "xmlns:simu=\""
						+ IRONNMAP_SIMU_METADATA_NS_URI
						+ "\" "
						+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
						+ "xsi:schemaLocation=\"http://www.example.com/extended-identifiers example-identifiers-2.1v1.xsd\" "
						+ "/>";
			}
		}
		return extendedIdentifierXmlImplementation;
	}

	/**
	 * Helper method to create implementation(Operating System) xml string for simu implementation identifier
	 * 
	 * @param ip
	 *            ip
	 * @param host
	 *            current host
	 * @return xmlString
	 */
	protected String createOsSimuImplementationXml(Identifier ip, Host host) {
		String extendedIdentifierXmlImplementation = null;
		String name = "";
		String version = "";
		String localVersion = "";
		String platform = "";

		if (ip instanceof IpAddress) {
			if (host.getOs().getOsMatches() != null) {
				name = host.getOs().getOsMatches().get(0).getName();
				platform = host.getOs().getOsClasses().get(0).getVendor();
				extendedIdentifierXmlImplementation = "<simu:implementation "
						+ "administrative-domain=\""
						+ ip
						+ "\" "
						+ "name=\""
						+ name
						+ "\" "
						+ "version=\""
						+ version
						+ "\" "
						+ "local-version=\""
						+ localVersion
						+ "\" "
						+ "platform=\""
						+ platform
						+ "\" "
						+ "xmlns:simu=\""
						+ IRONNMAP_SIMU_METADATA_NS_URI
						+ "\" "
						+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
						+ "xsi:schemaLocation=\"http://www.example.com/extended-identifiers example-identifiers-2.1v1.xsd\" "
						+ "/>";
			}
		}
		return extendedIdentifierXmlImplementation;
	}

}
