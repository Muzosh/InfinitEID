# web-eid-javacard-applet

This repository contains JavaCard applet designed to work with [Web-eID](https://web-eid.eu/) solution.

It consists of two sub-projects (having corresponding `README.md` in each sub-project) in the `src` directory:

1) JavaCard applet source code and build files
2) Python management console (card initialization and sending APDU commands)

Currently the applet works fine with tweaked web-eid-app (install instructions [here](https://github.com/Muzosh/libelectronic-id-with-custom-java-card)).

## General Usage

1. build and (re)install JavaCard applet (in `src/webeid-applet`):
   * `ant -f ./build.xml`
   * `java -jar ./gp.jar --uninstall ./webeid-applet.cap`
   * `java -jar ./gp.jar --install ./webeid-applet`
1. initialize card with Python management console by running `src/webeid-card-management/bin/cli` and selecting initialize option

### M1 macbooks

`gp.jar` does not work with M1 versions of Java properly, so x86-64 version must be installed. For compatibility reasons, I also chose Java 8:

1. download and install Amazon Correto 8 for macOS x86 from: <https://corretto.aws/downloads/latest/amazon-corretto-8-x64-macos-jdk.pkg>
1. add this line to `.zshrc` or other corresponding terminal source file: `alias gp="/Library/Java/JavaVirtualMachines/amazon-corretto-8.jdk/Contents/Home/bin/java -jar <replace-this-with-path-to-src/webeid-applet/gp.jar>"`
