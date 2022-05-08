package temp;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class WebeidAppletOld extends Applet {
    private RandomData rnd;

    public static void install(byte[] ba, short ofs, byte len) {
        (new WebeidAppletOld()).register();
    }

    private WebeidAppletOld() {
        rnd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        byte[] buf = apdu.getBuffer(); // contains first 5 APDU bytes
        switch (buf[ISO7816.OFFSET_INS]) {
            case (byte) 0x00:
                if (buf[ISO7816.OFFSET_LC] != (byte) 1) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                apdu.setIncomingAndReceive(); // read APDU data bytes
                short len = (short) (buf[ISO7816.OFFSET_CDATA] & (short) 0xff); // get rid of sign
                rnd.generateData(buf, (short) 0, len);
                apdu.setOutgoingAndSend((short) 0, len); // return response data
                return;
            case (byte) ISO7816.INS_SELECT:
                if (buf[ISO7816.OFFSET_P1] == 0x00) {
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
                }
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}