# Java APK integrity checker / app comparator

The aim is to check mutliple APK files in order to know if they refer to the same official Android app

* check integrity of a list of apk files
* compare public keys between mutliple apk files

TODO : parse Android binary XML

<b>Usage</b>

java -jar apkChecker.jar -l <apks> <options>

<table>
	<tr>
		<td>-l / -list</td><td>list of jars with separated with empty space(s)</td>
	</tr>
	<tr>
		<td>-v / -verify</td><td>verify java archive</td>
	</tr>
	<tr>
		<td>-c / -comparePubkey</td><td>compare public keys of jars</td>
	</tr>
</table>

Exemple : ``java -jar ./apkchecker-1.0.jar -l ~/test/app-debug.apk ~/test/app-debug3.apk -v -c``

<b>Output Exemples</b>

![exemple_success](https://raw.github.com/bertrandmartel/apk-checker/master/success.png)

![exemple_failure](https://raw.github.com/bertrandmartel/apk-checker/master/failure.png)

<b>Library used</b>

* rewrite of JarSigner by Sun Microsystems under GPLv2 License
* android-sun-jarsign-support-1.1.jar for JarSigner dependencies (NetscapeCertTypeExtension)
* sun.misc.BASE64Decoder.jar for Base64

<i>JDK 1.7</i>
<i>Eclipse</i>
