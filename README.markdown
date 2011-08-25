Spongy Castle - a repackage of Bouncy Castle for Android
========================================================

This project aims to be a full replacement for the crippled versions of the Bouncy Castle cryptographic libraries which ship with Android. As noted here:

http://code.google.com/p/android/issues/detail?id=3280

...the Android platform unfortunately incorporates a cut-down version of Bouncy Castle, which also makes installing an updated version of the libraries difficult due to classloader conflicts.

Spongy Castle is the stock Bouncy Castle libraries with a couple of small changes to make it work on Android:

- all package names have been moved from org.bouncycastle.* to org.spongycastle.* - so no classloader conflicts
- the Java Security API Provider name is now **SC** rather than **BC**

No class names have been changed, so the BouncyCastleProvider class remains Bouncy, not Spongy, but moves to the org.spongycastle.jce.provider package. 

#### Downloads

You can directly download the latest jar [here](http://search.maven.org/remotecontent?filepath=com/madgag/scprov-jdk15/1.46.99.3-UNOFFICIAL-ROBERTO-RELEASE/scprov-jdk15-1.46.99.3-UNOFFICIAL-ROBERTO-RELEASE.jar) (this is just a link to the published artifact in Maven Central).

#### Using Spongy Castle

You register it just the same as the standard BouncyCastleProvider:

	static {
		Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
	}

You can see an example of Spongy Castle in active use in the [toy-android-ssh-agent](https://github.com/rtyley/toy-android-ssh-agent) project:

https://github.com/rtyley/toy-android-ssh-agent/blob/d768a9ba853272d396f3b528eb991ea38244e6bc/src/main/java/com/madgag/ssh/toysshagent/ToyAuthAgentService.java#L28

There's also an even simpler demo project showing how to include Spongy Castle in a vanilla Eclipse project:

https://github.com/rtyley/spongycastle-eclipse#readme

#### Maven

Spongy Castle artifacts have been published to Maven Central, you can use [scprov-jdk15](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.madgag%22%20AND%20a%3A%22scprov-jdk15%22) as a drop-in replacement for the official Bouncy Castle artifact [bcprov-jdk15](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.bouncycastle%22%20a%3A%22bcprov-jdk15%22).

I suggest you use the [maven-android-plugin](http://code.google.com/p/maven-android-plugin/) to make the most of this :-)

#### Licence

Bouncy Castle uses an [adaptation of the MIT X11 License](http://www.bouncycastle.org/licence.html) and as Spongy Castle is a simple re-package of Bouncy Castle, you should consider it to be licenced under those same terms.

#### Projects using Spongy Castle

[JMRTD for Android](http://martijno.blogspot.com/2011/07/jmrtd-for-android.html)
