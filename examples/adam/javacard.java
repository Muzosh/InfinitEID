package appcrypto;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

// took x.y hours (please specify here how much time your solution required)


public class TestApplet extends Applet {
	
	private KeyPair keypair;
	private RSAPublicKey pub;
	private Cipher rsa;
	
	
	public static void install(byte[] ba, short offset, byte len) {
		(new TestApplet()).register();
	}

	private TestApplet() {
	}
	
	public void process(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		
		switch (buf[ISO7816.OFFSET_INS]) {
		case (0x02):
			keypair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
			keypair.genKeyPair();
			return;
		case (0x04):
			pub = (RSAPublicKey) keypair.getPublic();
			short e = pub.getExponent(buf, (short)0);
			apdu.setOutgoingAndSend((short)0, e);
			return;
		case (0x06):
			pub = (RSAPublicKey) keypair.getPublic();
			short m = pub.getModulus(buf, (short)0);
			apdu.setOutgoingAndSend((short)0, m);
			return;
		case (0x08):
			byte[] head = JCSystem.makeTransientByteArray((short)0x02, JCSystem.CLEAR_ON_DESELECT);
			byte[] data = JCSystem.makeTransientByteArray((short)0xfe, JCSystem.CLEAR_ON_DESELECT);	
			Util.arrayCopyNonAtomic(buf, (short)0x02, head, (short)0x00, (short)0x02);
			apdu.setIncomingAndReceive();
			Util.arrayCopyNonAtomic(buf, (short)0x05, data, (short)0, (short)0xfe);
			Util.arrayCopyNonAtomic(head, (short)0, buf, (short)0, (short)0x02);
			Util.arrayCopyNonAtomic(data, (short)0, buf, (short)0x02, (short)0xfe);
			rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			rsa.init(keypair.getPrivate(), Cipher.MODE_DECRYPT);
			short outlen = rsa.doFinal(buf, (short)0, (short)256,buf, (short)0);
			apdu.setOutgoingAndSend((short)0, outlen);
			return;
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);		
	}
}
