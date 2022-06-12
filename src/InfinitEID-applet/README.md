# InfinitEID-applet

This project provides JavaCard applet capable of communicating with [Web-eID](https://web-eid.eu/) solution.

> Web-eID app needs to be tweaked in order to accept InfinitEID: <https://github.com/Muzosh/libelectronic-id-with-InfinitEID>

## Applet functionality

* can handle long APDU in both communication protocols via
    * chaining APDUs
    * extended APDUS
* two keypairs
    * for authentication
    * for digital signature
* two certificates for public keys
* currently EC384 is implemented
* auth, sign and admin PIN
    * maximum PIN size
    * maximum retries + block/unblock
    * changing PIN
* reading and writing binary data (currently used for certificates)

## File structure description

* `jcdocs` = directory containing source files for used javacard API reference documentation, start with `index.html` file inside
* `sdks` = submodule from [here](https://github.com/martinpaljak/oracle_javacard_sdks)
* `src/InfinitEID/InfinitEIDApplet.java` = source code for JavaCard applet
* `ant-javacard.jar` = ant task for building JavaCard CAP files from [here](https://github.com/martinpaljak/ant-javacard)
* `build.xml` = build definition for CAP file (used for `ant` command)
* `gp.jar` = used for loading and managing CAP files on the card from [here](https://github.com/martinpaljak/GlobalPlatformPro)
* `InfinitEID-applet.cap` = builded CAP file ready to be loaded on JavaCard with GP

## Usage

1. update sdks submodule
   * `git submodule update --init sdks`
2. build JavaCard applet (in `src/InfinitEID-applet`):
   * `ant -f ./build.xml`
3. `InfinitEID-applet.cap` file with AID: 0102030405060708 should be generated in the same folder
4. (re)install applet to a JavaCard
   * `java -jar ./gp.jar --uninstall ./InfinitEID-applet.cap`
   * `java -jar ./gp.jar --install ./InfinitEID-applet`

### M1 macbooks

`gp.jar` does not work with M1 versions of Java properly, so x86-64 version must be installed. For compatibility reasons, I also chose Java 8:

1. download and install Amazon Correto 8 for macOS x86 from: <https://corretto.aws/downloads/latest/amazon-corretto-8-x64-macos-jdk.pkg>
1. add this line to `.zshrc` or other corresponding terminal source file: `alias gp="/Library/Java/JavaVirtualMachines/amazon-corretto-8.jdk/Contents/Home/bin/java -jar <replace-this-with-path-to-src/InfinitEID-applet/gp.jar>"`

## Similar projects/inspiration

Following repositories served as inspiration for creating this project (all of them are not maintained anymore):

* <https://github.com/martinpaljak/esteid-applets>
* <https://github.com/philipWendland/IsoApplet>
* <https://github.com/amoerie/belgian-e-id>
* <https://github.com/Twuk/eid-quick-key-toolset>
