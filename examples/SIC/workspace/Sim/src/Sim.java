/**
 * Created by nversbra on 3/7/17.
 */


import be.msec.smartcard.IdentityCard;
import com.licel.jcardsim.smartcardio.*;
import com.licel.jcardsim.utils.*;
import com.licel.jcardsim.base.*;
import javacard.framework.*;
import javacard.security.*;
import javax.smartcardio.*;

public class Sim {

    public static void main(String[] args) throws Exception {

        CardSimulator sim = new CardSimulator();
        AID appletAID = AIDUtil.create("F000000001");
        sim.installApplet(appletAID, IdentityCard.class);
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
        ResponseAPDU response = sim.transmitCommand(commandAPDU);
        System.out.println(response);
    }
}
