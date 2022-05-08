# SIC
Security in computing; A privacy-friendly alternative for the Belgian eID card.
The project aims to improve security of Belgian ID holders by limiting the current extensive exposure of their profiles. To do so, we build an alternative ID card which limits service providers to strickly necessary ID holder profile information.

This is a project from a Seurity in Computing course at the VUB.


Running Instructions: 

The SP server and the Timestamp server need to be running before running an application with the eID. The SP server is run using Tomcat (for instructions see http://tomcat.apache.org or http://www.vogella.com/tutorials/ApacheTomcat/article.html) the necessary .war file is available along the source code.  The TS server is built as a regular java command-line application and can thus be run accordingly (see e.g. Windows: http://www.skylit.com/javamethods/faqs/javaindos.html Unix: http://introcs.cs.princeton.edu/java/15inout/linux-cmd.html. One can then proceed by running the simulator (see e.g. https://www.msec.be/wiscy/seminarie/tut.pdf) and running the SPRequest.java file . Now, via a browser, navigate to http://localhost:8088 (or the port specified in your Tomcat configuration). You should now be presented with a list of providers, which are all clickable, and will redirect you to a page where the desired service and attributes can be selected.  
