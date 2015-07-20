package de.hshannover.f4.trust.ironnmap.subscriber.strategies;

import java.util.logging.Logger;

import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.IpAddress;
import de.hshannover.f4.trust.ifmapj.identifier.MacAddress;
import de.hshannover.f4.trust.ironcommon.properties.PropertyException;
import de.hshannover.f4.trust.ironnmap.publisher.strategies.ScanSingleTime;
import de.hshannover.f4.trust.ironnmap.subscriber.SubscriberNmapStrategy;

public class SubscriberOsNmapScanStrategy extends SubscriberNmapStrategy {

	private static final Logger LOGGER = Logger.getLogger(SubscriberOsNmapScanStrategy.class.getName());

	private static final String SUBSCRIBERNAME = "nmap_OsScan";

	private static final String SUBSCRIBERFILTER = "meta:request-for-investigation[@qualifier='nmap_OsScan']";

	@Override
	protected String getSubscriberName() {
		return SUBSCRIBERNAME;
	}

	@Override
	protected String getSubscriberFilter() {
		return SUBSCRIBERFILTER;
	}

	@Override
	protected void scanWithStrategy(SSRC ssrc, Identifier ipOrMac) {
		try {
			if (ipOrMac instanceof IpAddress) {
				IpAddress ip = (IpAddress) ipOrMac;

				ScanSingleTime scan = new ScanSingleTime(ip.getValue(), "", "-sV -PN -O");
				scan.publishNmapStrategy(ssrc);

			} else if (ipOrMac instanceof MacAddress) {
				MacAddress mac = (MacAddress) ipOrMac;
				ScanSingleTime scan = new ScanSingleTime(mac.getValue(), "", "-sV -PN -O");
				scan.publishNmapStrategy(ssrc);
			}
		} catch (PropertyException e) {
			LOGGER.severe("Couldn't read property");
		}
	}

}
