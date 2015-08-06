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
package de.hshannover.f4.trust.ironnmap.subscriber;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.hshannover.f4.trust.ifmapj.binding.IfmapStrings;
import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.identifier.Device;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.identifier.IpAddress;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ifmapj.messages.ResultItem;
import de.hshannover.f4.trust.ifmapj.messages.SearchResult;
import de.hshannover.f4.trust.ifmapj.messages.SubscribeRequest;
import de.hshannover.f4.trust.ifmapj.messages.SubscribeUpdate;
import de.hshannover.f4.trust.ironnmap.utilities.IfMap;

/**
 * This abstract class is an abstract represent of the Implementation of the different subscriber strategies to set
 * firewall entries on the floodlight openflow controller
 * 
 * @author Marius Rohde
 * 
 */

public abstract class SubscriberNmapStrategy {

	private static final Logger LOGGER = LogManager.getLogger(SubscriberNmapStrategy.class.getName());

	/**
	 * Method to initialize the subscriber function on the Ifmap server
	 * 
	 */
	public void initSubscriber(String subscriptionroot) {

		LOGGER.debug("subscribing for " + subscriptionroot);

		Device startIdentifier = Identifiers.createDev(subscriptionroot);

		SubscribeRequest subscribeRequest = Requests.createSubscribeReq();
		SubscribeUpdate subscribeUpdate = Requests.createSubscribeUpdate();
		subscribeUpdate.setName(getSubscriberName());
		subscribeUpdate.setMatchLinksFilter(getSubscriberFilter());
		subscribeUpdate.setMaxDepth(1);
		subscribeUpdate.setStartIdentifier(startIdentifier);

		subscribeUpdate.addNamespaceDeclaration(IfmapStrings.BASE_PREFIX, IfmapStrings.BASE_NS_URI);
		subscribeUpdate.addNamespaceDeclaration(IfmapStrings.STD_METADATA_PREFIX, IfmapStrings.STD_METADATA_NS_URI);

		subscribeRequest.addSubscribeElement(subscribeUpdate);

		try {
			IfMap.getSsrc().subscribe(subscribeRequest);
		} catch (IfmapErrorResult e) {
			LOGGER.fatal("SubscriberStrategy: " + e);
		} catch (IfmapException e) {
			LOGGER.fatal("SubscriberStrategy: " + e);
		}
	}

	/**
	 * Method to execute the nmap scan
	 * 
	 * @param searchResult
	 *            with empty resultitems
	 * 
	 */
	public void executeNmapScanStrategy(SSRC ssrc, SearchResult searchResult) {

		if (searchResult.getName().equals(getSubscriberName())) {
			List<ResultItem> cleanedResultItems = cleanEmptySearchResult(searchResult);

			for (ResultItem resultItem : cleanedResultItems) {
				if (resultItem.getIdentifier1() instanceof IpAddress) {
					scanWithStrategy(ssrc, resultItem.getIdentifier1());
				} else if (resultItem.getIdentifier2() instanceof IpAddress) {
					scanWithStrategy(ssrc, resultItem.getIdentifier2());
				}
			}
		}
	}

	/**
	 * Helper method to clean the searchResult from the empty ResultItems
	 * 
	 * @return the ArrayList of ResultItems from a SearchResult
	 */
	private List<ResultItem> cleanEmptySearchResult(SearchResult searchResult) {
		List<ResultItem> resultItems = new ArrayList<ResultItem>();

		for (ResultItem resultItem : searchResult.getResultItems()) {
			if (!resultItem.getMetadata().isEmpty()) {
				resultItems.add(resultItem);
			}
		}

		return resultItems;
	}

	/**
	 * Method to get the Strategie subscribername from the implementation class of the Subscriber
	 * 
	 * @return the name of the subscriber
	 */
	protected abstract String getSubscriberName();

	/**
	 * Method to get the Strategie subscriber Filter from the implementation class of the Subscriber to define the
	 * Request for Investigation qualifier name
	 * 
	 * @return the name of the subscriber
	 */
	protected abstract String getSubscriberFilter();

	/**
	 * Method to execute the nmap scan
	 * 
	 * @param ipOrMac
	 *            resultitem Identifier mac or ip
	 * 
	 */
	protected abstract void scanWithStrategy(SSRC ssrc, Identifier ipOrMac);

}
