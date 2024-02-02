# BurpJDSer-ng-edited

A Burp Suite plugin that deserialize Serialized Java objects and convert them in an XML format (using XStream library). Based on BurpJDSer-ng of [omercnet](https://github.com/omercnet/BurpJDSer-ng) and on BurpJDSer of [khai-tran](https://github.com/khai-tran/BurpJDSer), with some fixes and the addiction of some code to unpack requests and responses, if packed with gzip.

## Usage (new Burp Suite versions)

1) Download XStream library (https://mvnrepository.com/artifact/com.thoughtworks.xstream/xstream). Tested with version 1.4.20.

2) Download jar files of target applet (usually this can be done viewing HTML response from the page that loads Java applet and searching for the applet tag, but can be different in other cases like Java Web Start)

3) Edit *BurpSuitePro.vmoptions* file in the Burp Suite installation folder, adding the following line at the end of the file (replace ':' separator with ';' on Windows):

```
-classpath ".:<HOME>/BurpSuitePro/burpsuite_pro.jar:<XSTREAM_FOLDER>/xstream-1.4.20.jar:<APPLET_JAR_FOLDER>/appletJar1.jar:<APPLET_JAR_FOLDER>/appletJar2.jar"
```

where:
* "<HOME>/BurpSuitePro/burpsuite_pro.jar" is the path of Burp Suite jar file in the Burp Suite installation folder
* "<XSTREAM_FOLDER>/xstream-1.4.20.jar" is the path of XStream jar file
* "<APPLET_JAR_FOLDER>/appletJar1.jar" and "<APPLET_JAR_FOLDER>/appletJar2.jar" are the paths of target applet jar files (in this example 2 jar files). In case of more jars, include all in classpath or use wildcards

4) Run Burp Suite

5) In the Extender TAB of Burp Suite, add the plugin

6) If a serialized request will be detected, a new tab will appear with an XML representation of the Serialized Java Object. The same thing applies also for the responses. The plugin will work also if requests and responses are packed with gzip. You can also intercept and edit the requests/responses or use the Repeater. The plugin will automatically re-serialize edited requests/responses.


## Usage (old Burp Suite v1)

1) Download XStream library (http://xstream.codehaus.org). Tested with version 1.4.4.

2) Download jar files of target applet (usually this can be done viewing HTML response from the page that loads Java applet and searching for the applet tag, but can be different in other cases like Java Web Start)

3) Execute Burp Suite in the following way:

java -Xmx512m -classpath "PATH_BURP_JAR;PATH_XSTREAM_JAR;PATH_APPLET_JAR" burp.StartBurp

where:
* PATH_BURP_JAR is the path of Burp Suite jar file
* PATH_XSTREAM_JAR is the path of XStream jar file
* PATH_APPLET_JAR is the path of target applet jar file. In case of more jars, include all in classpath or use wildcards

4) In the Extender TAB of Burp Suite, add the plugin

5) If a serialized request will be detected, a new tab will appear with an XML representation of the Serialized Java Object. The same thing for the responses, but it will work also if the response will be packed with gzip. You can also intercept and edit the request or use the Repeater. The plugin will automatically reserialize edited requests.
