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

import java.util.ArrayList;

import org.nmap4j.Nmap4j;
import org.nmap4j.core.nmap.NMapExecutionException;
import org.nmap4j.core.nmap.NMapInitializationException;
import org.nmap4j.data.NMapRun;

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

	@Override
	public void publishNmapStrategy(String ipFrom, String ipTill, ArrayList<String> nmapFlags) {
		// TODO Auto-generated method stub

		Nmap4j nmap4j = new Nmap4j("/usr");
		nmap4j.includeHosts("192.168.1.240");
		nmap4j.addFlags("-T3 -oN -sV");
		
		try {
			nmap4j.execute();
		} catch (NMapInitializationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NMapExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if (!nmap4j.hasError()) {
			NMapRun nmapRun = nmap4j.getResult();
			System.out.println(nmap4j.getOutput());
			System.out.println(nmapRun);
		} else {
			System.out.println(nmap4j.getExecutionResults().getErrors());
		}
	}
}