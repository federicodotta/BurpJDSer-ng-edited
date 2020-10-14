# BurpJDSer-ng-edited

A Burp Suite plugin that **deserializes** and **un-gzips** (if necessary) Serialized Java objects, and displays them in an XML format. It also allows to **modify contents** and re-serialize / re-gzip.

Based on BurpJDSer-ng-edited of [federicodotta](https://github.com/federicodotta/BurpJDSer-ng-edited), [omercnet](https://github.com/omercnet/BurpJDSer-ng) and on BurpJDSer of [khai-tran](https://github.com/khai-tran/BurpJDSer).

## Usage

1) Download XStream library version 1.4.4 from the xstream directory

2) Download the jar files of your target application (usually this can be done viewing HTML responses from the page that loads the Java application, but can be different in other cases like Java Web Start)

3) Execute Burp Suite with the following command:

`java -Xmx512m -classpath "PATH_BURP_JAR;PATH_XSTREAM_JAR;PATH_APPLICATION_JAR" burp.StartBurp`

where:
* PATH_BURP_JAR is the path of Burp Suite jar file
* PATH_XSTREAM_JAR is the path of XStream jar file
* PATH_APPLICATION_JAR is the path of target application jar file. In case there are multiple jars file, include them all in the classpath or use wildcards

4) In the Extender TAB of Burp Suite, add the plugin

5) If a serialized and potentially gzipped request/response is detected, a new tab will appear with an XML representation of the Serialized Java Object. You can also intercept and edit the request or use the Repeater, as the plugin will automatically reserialize et regzip edited requests.
