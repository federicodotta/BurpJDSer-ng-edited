# BurpJDSer-ng-edited

A Burp Suite plugin that **deserializes** and **un-gzips** (if necessary) Serialized Java objects, and displays them in an XML format. It also allows to **modify contents** and re-serialize / re-gzip.

Based on BurpJDSer-ng-edited of [federicodotta](https://github.com/federicodotta/BurpJDSer-ng-edited), [omercnet](https://github.com/omercnet/BurpJDSer-ng) and on BurpJDSer of [khai-tran](https://github.com/khai-tran/BurpJDSer).

## Usage

1) Download XStream library (http://xstream.codehaus.org). Tested with version 1.4.4.

2) Download jar files of target applet (usually this can be done viewing HTML response from the page that loads Java applet and searching for the applet tag, but can be different in other cases like Java Web Start)

3) Execute Burp Suite in the following way:

java -Xmx512m -classpath "PATH_BURP_JAR;PATH_XSTREAM_JAR;PATH_APPLET_JAR" burp.StartBurp

where:
* PATH_BURP_JAR is the path of Burp Suite jar file
* PATH_XSTREAM_JAR is the path of XStream jar file
* PATH_APPLET_JAR is the path of target applet jar file. In case of more jars, include all in classpath or use wildcards

4) In the Extender TAB of Burp Suite, add the plugin

5) If a serialized request will be detected, a new tab will appearwith an XML rappresentation of the Serialized Java Object. The same thing for the responses, but it will work also if the response will be packed with gzip. You can also intercept and edit the request or use the Repeater. The plugin will automatically reserialize edited requests.
