# ironnmap
=======

ironnmap is a *highly experimental* software that integrates nmap scan informations
into a MAP-Infrastructure. The integration aims to share security related informations,
given by the scan of a host or network, with other network components in the 
[TNC architecture] [1] via IF-MAP.

ironnmap consists of two elements:

* The "publisher" - simply fetches the latest informations provided by
  a nmap scan and converts the informations in it into IF-MAP metadata that finally will
  be published into a MAP server.
  
  Ironnmap will update the Metadata informations a single time if it is called per cli 
  with the singletime parameter. In other words this means that ironnmap can be activated manually
  by an administrator to generate informations about a host or network on demand.

* The "subscriber" - subscribes for request for investigation metadata on ip addresses,
  which signalises that a scan of that ip/host is required.
  
  In this mode the system automatically reacts on events to enhance the informations about hosts 
  in your IF-MAP metadata structure. The provided scan method is the operating system scan offered
  by nmap with the option -O.

The binary package (`ironnmap-x.x.x-bundle.zip`) of ironnmap
is ready to run, all you need is to configure it to your needs.
If you like to build ironnmap by your own you can use the
latest code from the [GitHub repository][githubrepo].


Requirements
============
To use the binary package of ironnmap you need the following components:

* OpenJDK Version 1.7 or higher
* nmap 6.4 [2]
* MAP server implementation (e.g. [irond] [3])
* optionally ironGui or visitMeta to see whats going on

If you have downloaded the source code and want to build ironnmap by
yourself Maven 3 is also needed.


Configuration
=============
To setup the binary package you need to import the Ironnmap and MAP server
certificates into `ironnmap.jks`.
If you want to use ironnmap with irond the keystores of both are configured 
with ready-to-use testing certificates.

The remaining configuration parameters can be done through the
`ironnmap.yml` file in the ironnmap package.
In general you have to specify:

* the nmap installation path,
* the MAPS URL and credentials.

Have a look at the comments in `ironnmap.yml`

Secondly you have to setup nmap.

Building
========
You can build ironnmap by executing:

    $ mvn package

in the root directory of the ironnmap project.
Maven should download all further needed dependencies for you. After a successful
build you should find the `ironnmap-x.x.x-bundle.zip` in the `target` sub-directory.


Running
=======
To run the binary package of ironnmap simply execute:

    $ ./start.sh

or execute ironnmap with java -jar ironnmap with following parameters.

    use of ironnmap [-h] [-purgePublisher [{purge,nopurge}]]
                    -inc INCLUDE [-exc EXCLUDE]
                    [{singleTime,multiTime}] [flags [flags ...]]
                    
-purgePublisher = purge previous published data on startup #Default: nopurge  
-inc = included network address(es) to scan network like 192.168.0.0/24  
-exc = exclud network addresses from the include list  
singleTime = single time scan (only works with cli)  #Default: multitime (only works with subscriber mode)  
flags -- = all flags of nmap are possible(not all are supported)  

an example could look like:  
    singleTime -inc 192.168.1.13 -purgePublisher purge  flags -- -A

Please note that some flags needs administrator rights to be execute like Operating System Scan (-O)

Feedback
========
If you have any questions, problems or comments, please contact
    <trust@f4-i.fh-hannover.de>


LICENSE
=======
ironnmap is licensed under the [Apache License, Version 2.0] [4].


Note
====

ironnmap is an experimental prototype and is not suitable for actual use.

Feel free to fork/contribute.


Notes on nmap4j
===============

This software uses and delivers nmap4j.
The license of the nmap4j implementation is attached in NOTICE file.

[1]: http://www.trustedcomputinggroup.org/developers/trusted_network_connect
[2]: https://nmap.org/
[3]: https://github.com/trustathsh/irond
[4]: http://www.apache.org/licenses/LICENSE-2.0.html
[githubrepo]: https://github.com/trustathsh/ironnmap