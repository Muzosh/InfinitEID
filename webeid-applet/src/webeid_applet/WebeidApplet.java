package webeid_applet;
import javacard.framework.*;
import javacard.security.*;

public class WebeidApplet extends Applet {

    public static void install(byte[] ba, short ofs, byte len) {
        (new WebeidApplet()).register();
    }

    private WebeidApplet() {
    }

    public void process(APDU apdu) {
    }
}
