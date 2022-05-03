package webeidapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;

public class WebeidApplet extends Applet {
	// Interesting Data (tm)
	private KeyPair auth;
	private KeyPair sign;
	private Cipher rsa;
	private byte[] authcert;
	private byte[] signcert;

	// TODO: actually maintain the PIN values?
	private byte[] pin1 = new byte[13]; // +1 for length
	private byte[] pin2 = new byte[13];
	private byte[] puk = new byte[13];

	// Less interesting objects
	// File identifiers that are used by baastarkvara
	private final  short FID_3F00 = (short) 0x3F00;
	private final  short FID_0013 = (short) 0x0013;
	private final  short FID_0016 = (short) 0x0016;
	private final  short FID_EEEE = (short) 0xEEEE;
	private final  short FID_5044 = (short) 0x5044;
	private final  short FID_AACE = (short) 0xAACE;
	private final  short FID_DDCE = (short) 0xDDCE;
	private final  short FID_0033 = (short) 0x0033;

	// FCI bytes;
	public  final byte[] fci_mf = new byte[] { (byte) 0x6F, (byte) 0x26,
		(byte) 0x82, (byte) 0x01, (byte) 0x38, (byte) 0x83, (byte) 0x02,
		(byte) 0x3F, (byte) 0x00, (byte) 0x84, (byte) 0x02, (byte) 0x4D,
		(byte) 0x46, (byte) 0x85, (byte) 0x02, (byte) 0x57, (byte) 0x3E,
		(byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1, (byte) 0x03,
		(byte) 0x8B, (byte) 0x01, (byte) 0x02, (byte) 0x81, (byte) 0x08,
		(byte) 0xD2, (byte) 0x76, (byte) 0x00, (byte) 0x00, (byte) 0x28,
		(byte) 0xFF, (byte) 0x05, (byte) 0x2D, (byte) 0x82, (byte) 0x03,
		(byte) 0x03, (byte) 0x00, (byte) 0x00 };
	public  final byte[] fci_eeee = new byte[] { (byte) 0x6F,
		(byte) 0x25, (byte) 0x82, (byte) 0x01, (byte) 0x38, (byte) 0x83,
		(byte) 0x02, (byte) 0xEE, (byte) 0xEE, (byte) 0x84, (byte) 0x10,
		(byte) 0xD2, (byte) 0x33, (byte) 0x00, (byte) 0x00, (byte) 0x01,
		(byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x85, (byte) 0x02, (byte) 0x57, (byte) 0x3E,
		(byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1, (byte) 0x03,
		(byte) 0x8B, (byte) 0x01, (byte) 0x02 };
	public  final byte[] fci_aace = new byte[] { (byte) 0x62,
		(byte) 0x18, (byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x83,
		(byte) 0x02, (byte) 0xAA, (byte) 0xCE, (byte) 0x85, (byte) 0x02,
		(byte) 0x06, (byte) 0x00, (byte) 0x8A, (byte) 0x01, (byte) 0x05,
		(byte) 0xA1, (byte) 0x08, (byte) 0x8B, (byte) 0x06, (byte) 0x00,
		(byte) 0x30, (byte) 0x03, (byte) 0x06, (byte) 0x00, (byte) 0x01 };
	public  final byte[] fci_ddce = new byte[] { (byte) 0x62,
		(byte) 0x18, (byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x83,
		(byte) 0x02, (byte) 0xDD, (byte) 0xCE, (byte) 0x85, (byte) 0x02,
		(byte) 0x06, (byte) 0x00, (byte) 0x8A, (byte) 0x01, (byte) 0x05,
		(byte) 0xA1, (byte) 0x08, (byte) 0x8B, (byte) 0x06, (byte) 0x00,
		(byte) 0x30, (byte) 0x03, (byte) 0x06, (byte) 0x00, (byte) 0x01 };
	public  final byte[] fci_5044 = new byte[] { (byte) 0x62,
		(byte) 0x17, (byte) 0x82, (byte) 0x05, (byte) 0x04, (byte) 0x41,
		(byte) 0x00, (byte) 0x32, (byte) 0x10, (byte) 0x83, (byte) 0x02,
		(byte) 0x50, (byte) 0x44, (byte) 0x85, (byte) 0x02, (byte) 0x01,
		(byte) 0x8C, (byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1,
		(byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x01 };
	public  final byte[] fci_0016 = new byte[] { (byte) 0x62,
		(byte) 0x17, (byte) 0x82, (byte) 0x05, (byte) 0x04, (byte) 0x41,
		(byte) 0x00, (byte) 0x0C, (byte) 0x03, (byte) 0x83, (byte) 0x02,
		(byte) 0x00, (byte) 0x16, (byte) 0x85, (byte) 0x02, (byte) 0x00,
		(byte) 0x1A, (byte) 0x8A, (byte) 0x01, (byte) 0x05, (byte) 0xA1,
		(byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x01 };
	public  final byte[] fci_0013 = new byte[] { (byte) 0x62,
		(byte) 0x18, (byte) 0x82, (byte) 0x05, (byte) 0x02, (byte) 0x41,
		(byte) 0x00, (byte) 0x4F, (byte) 0x04, (byte) 0x83, (byte) 0x02,
		(byte) 0x00, (byte) 0x13, (byte) 0x8A, (byte) 0x01, (byte) 0x05,
		(byte) 0xA1, (byte) 0x08, (byte) 0x8B, (byte) 0x06, (byte) 0x00,
		(byte) 0x30, (byte) 0x03, (byte) 0x07, (byte) 0x00, (byte) 0x01 };

	public  final byte[] fci_0033 = new byte[] { (byte) 0x62,
		(byte) 0x18, (byte) 0x82, (byte) 0x05, (byte) 0x02, (byte) 0x41,
		(byte) 0x00, (byte) 0x15, (byte) 0x01, (byte) 0x83, (byte) 0x02,
		(byte) 0x00, (byte) 0x33, (byte) 0x8A, (byte) 0x01, (byte) 0x05,
		(byte) 0xA1, (byte) 0x08, (byte) 0x8B, (byte) 0x06, (byte) 0x00,
		(byte) 0x30, (byte) 0x03, (byte) 0x07, (byte) 0x00, (byte) 0x01 };

	// Records of EEEE/0013
	public  final byte[] eeee_0013_1 = new byte[] { (byte) 0x83,
		(byte) 0x04, (byte) 0x01, (byte) 0x00, (byte) 0x10, (byte) 0x01,
		(byte) 0xC0, (byte) 0x02, (byte) 0x81, (byte) 0x80, (byte) 0x91,
		(byte) 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x7B,
		(byte) 0x18, (byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0xA1,
		(byte) 0x0A, (byte) 0x8B, (byte) 0x08, (byte) 0x00, (byte) 0x30,
		(byte) 0x01, (byte) 0x03, (byte) 0x02, (byte) 0x04, (byte) 0x03,
		(byte) 0x05, (byte) 0xB6, (byte) 0x07, (byte) 0x95, (byte) 0x01,
		(byte) 0x40, (byte) 0x89, (byte) 0x02, (byte) 0x13, (byte) 0x10,
		(byte) 0x7B, (byte) 0x11, (byte) 0x80, (byte) 0x01, (byte) 0x06,
		(byte) 0xA1, (byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x09,
		(byte) 0xB8, (byte) 0x07, (byte) 0x95, (byte) 0x01, (byte) 0x40,
		(byte) 0x89, (byte) 0x02, (byte) 0x11, (byte) 0x30, (byte) 0x7B,
		(byte) 0x11, (byte) 0x80, (byte) 0x01, (byte) 0x07, (byte) 0xA1,
		(byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x0A, (byte) 0xB8,
		(byte) 0x07, (byte) 0x95, (byte) 0x01, (byte) 0x40, (byte) 0x89,
		(byte) 0x02, (byte) 0x11, (byte) 0x30 };
	public  final byte[] eeee_0013_2 = new byte[] { (byte) 0x83,
		(byte) 0x04, (byte) 0x02, (byte) 0x00, (byte) 0x10, (byte) 0x02,
		(byte) 0xC0, (byte) 0x02, (byte) 0x81, (byte) 0x80, (byte) 0x91,
		(byte) 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x7B,
		(byte) 0x18, (byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0xA1,
		(byte) 0x0A, (byte) 0x8B, (byte) 0x08, (byte) 0x00, (byte) 0x30,
		(byte) 0x01, (byte) 0x03, (byte) 0x02, (byte) 0x04, (byte) 0x03,
		(byte) 0x05, (byte) 0xF6, (byte) 0x07, (byte) 0x95, (byte) 0x01,
		(byte) 0x40, (byte) 0x89, (byte) 0x02, (byte) 0x13, (byte) 0x10,
		(byte) 0x7B, (byte) 0x11, (byte) 0x80, (byte) 0x01, (byte) 0x06,
		(byte) 0xA1, (byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x09,
		(byte) 0xB8, (byte) 0x07, (byte) 0x95, (byte) 0x01, (byte) 0x40,
		(byte) 0x89, (byte) 0x02, (byte) 0x11, (byte) 0x30, (byte) 0x7B,
		(byte) 0x11, (byte) 0x80, (byte) 0x01, (byte) 0x07, (byte) 0xA1,
		(byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x0A, (byte) 0xB8,
		(byte) 0x07, (byte) 0x95, (byte) 0x01, (byte) 0x40, (byte) 0x89,
		(byte) 0x02, (byte) 0x11, (byte) 0x30 };
	public  final byte[] eeee_0013_3 = new byte[] { (byte) 0x83,
		(byte) 0x04, (byte) 0x11, (byte) 0x00, (byte) 0x10, (byte) 0x11,
		(byte) 0xC0, (byte) 0x02, (byte) 0x81, (byte) 0x80, (byte) 0x91,
		(byte) 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x7B,
		(byte) 0x18, (byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0xA1,
		(byte) 0x0A, (byte) 0x8B, (byte) 0x08, (byte) 0x00, (byte) 0x30,
		(byte) 0x01, (byte) 0x03, (byte) 0x02, (byte) 0x04, (byte) 0x03,
		(byte) 0x05, (byte) 0xA4, (byte) 0x07, (byte) 0x95, (byte) 0x01,
		(byte) 0x40, (byte) 0x89, (byte) 0x02, (byte) 0x21, (byte) 0x13,
		(byte) 0x7B, (byte) 0x11, (byte) 0x80, (byte) 0x01, (byte) 0x06,
		(byte) 0xA1, (byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x0B,
		(byte) 0xB8, (byte) 0x07, (byte) 0x95, (byte) 0x01, (byte) 0x40,
		(byte) 0x89, (byte) 0x02, (byte) 0x11, (byte) 0x30, (byte) 0x7B,
		(byte) 0x11, (byte) 0x80, (byte) 0x01, (byte) 0x07, (byte) 0xA1,
		(byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x0C, (byte) 0xB8,
		(byte) 0x07, (byte) 0x95, (byte) 0x01, (byte) 0x40, (byte) 0x89,
		(byte) 0x02, (byte) 0x11, (byte) 0x30 };
	public  final byte[] eeee_0013_4 = new byte[] { (byte) 0x83,
		(byte) 0x04, (byte) 0x12, (byte) 0x00, (byte) 0x10, (byte) 0x12,
		(byte) 0xC0, (byte) 0x02, (byte) 0x81, (byte) 0x80, (byte) 0x91,
		(byte) 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x7B,
		(byte) 0x18, (byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0xA1,
		(byte) 0x0A, (byte) 0x8B, (byte) 0x08, (byte) 0x00, (byte) 0x30,
		(byte) 0x01, (byte) 0x03, (byte) 0x02, (byte) 0x04, (byte) 0x03,
		(byte) 0x05, (byte) 0xE4, (byte) 0x07, (byte) 0x95, (byte) 0x01,
		(byte) 0x40, (byte) 0x89, (byte) 0x02, (byte) 0x21, (byte) 0x13,
		(byte) 0x7B, (byte) 0x11, (byte) 0x80, (byte) 0x01, (byte) 0x06,
		(byte) 0xA1, (byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x0B,
		(byte) 0xB8, (byte) 0x07, (byte) 0x95, (byte) 0x01, (byte) 0x40,
		(byte) 0x89, (byte) 0x02, (byte) 0x11, (byte) 0x30, (byte) 0x7B,
		(byte) 0x11, (byte) 0x80, (byte) 0x01, (byte) 0x07, (byte) 0xA1,
		(byte) 0x03, (byte) 0x8B, (byte) 0x01, (byte) 0x0C, (byte) 0xB8,
		(byte) 0x07, (byte) 0x95, (byte) 0x01, (byte) 0x40, (byte) 0x89,
		(byte) 0x02, (byte) 0x11, (byte) 0x30 };

	// Records of MF/0016
	public  final byte[] mf_0016_1 = new byte[] { (byte) 0x80,
		(byte) 0x01, (byte) 0x03, (byte) 0x90, (byte) 0x01, (byte) 0x03,
		(byte) 0x83, (byte) 0x02, (byte) 0x00, (byte) 0x00 };
	public  final byte[] mf_0016_2 = new byte[] { (byte) 0x80,
		(byte) 0x01, (byte) 0x03, (byte) 0x90, (byte) 0x01, (byte) 0x03,
		(byte) 0x83, (byte) 0x02, (byte) 0x00, (byte) 0x00 };
	public  final byte[] mf_0016_3 = new byte[] { (byte) 0x80,
		(byte) 0x01, (byte) 0x03, (byte) 0x90, (byte) 0x01, (byte) 0x03 };

	// Record of EEEE/0033
	public  final byte[] eeee_0033_1 = new byte[] { (byte) 0x00,
		(byte) 0xA4, (byte) 0x08, (byte) 0x95, (byte) 0x01, (byte) 0x40,
		(byte) 0x83, (byte) 0x03, (byte) 0x80, (byte) 0x11, (byte) 0x00,
		(byte) 0xB6, (byte) 0x08, (byte) 0x95, (byte) 0x01, (byte) 0x40,
		(byte) 0x83, (byte) 0x03, (byte) 0x80, (byte) 0x01, (byte) 0x00 };

	// AID
	public  final byte[] aid = new byte[] {(byte)0xD2, (byte)0x33, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x45, (byte)0x73, (byte)0x74, (byte)0x45, (byte)0x49, (byte)0x44, (byte)0x20, (byte)0x76, (byte)0x33, (byte)0x35};

	private short[] runtime_fields;
	private short selectedfile = 0;
	private byte [] ram = null; 
	
	private WebeidApplet() {
		auth = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
		sign = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
		// Not necessary, but be paranoid
		auth.getPrivate().clearKey();
		sign.getPrivate().clearKey();
		auth.getPublic().clearKey();
		sign.getPublic().clearKey();

		// Certificates
		authcert = new byte[0x600];
		Util.arrayFillNonAtomic(authcert, (short) 0, (short) authcert.length, (byte) 0x00);
		signcert = new byte[0x600];
		Util.arrayFillNonAtomic(signcert, (short) 0, (short) signcert.length, (byte) 0x00)

		// Operational fields
		runtime_fields = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
		rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		ram = JCSystem.makeTransientByteArray((short) 384, JCSystem.CLEAR_ON_RESET);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		WebeidApplet fake = new WebeidApplet();
		fake.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) throws ISOException {
		if (selectingApplet())
			return;

		byte[] buffer = apdu.getBuffer();

		switch (buffer[ISO7816.OFFSET_CLA]) {
		case (byte) 0x00: // ISO as described in specs
			process_command(apdu, buffer);
		break;
		case (byte) 0x80: // Proprietary: setting/getting values
			process_mock_commands(apdu, buffer);
		break;
		default:
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			break;
		}

	}

	// Commands that are executed by opensc/qesteidutil
	private void process_command(APDU apdu, byte[] buffer) {
		short len = 0;
		short len2 = 0;
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];

		switch (buffer[ISO7816.OFFSET_INS]) {
		case ISO7816.INS_SELECT:
			if (buffer[ISO7816.OFFSET_LC] == 0x02) {
				len = apdu.setIncomingAndReceive();
				// must be 2 bytes of input.
				short fid = Util.makeShort(buffer[5], buffer[6]);
				switch (fid) {
				case FID_3F00:
				case FID_EEEE:
				case FID_0013:
				case FID_0016:
				case FID_5044:
				case FID_AACE:
				case FID_DDCE:
				case FID_0033:
					runtime_fields[selectedfile] = fid;
					break;
				default:
					Pro.throwIt(ISO7816.SW_FILE_NOT_FOUND);
					break;
				}
			} else if (p1 == 0x04) {
				len = apdu.setIncomingAndReceive();
				if (!JCSystem.getAID().partialEquals(buffer, ISO7816.OFFSET_CDATA, (byte) len)) {
					Pro.throwIt(ISO7816.SW_FILE_NOT_FOUND);
				}
			}

			// Send FCI if asked
			if (p2 == 0x04 || p2 == 0x00) {
				switch (runtime_fields[selectedfile]) {
				case FID_3F00:
					Pro.send_array(fci_mf);
					break;
				case FID_AACE:
					Pro.send_array(fci_aace);
					break;
				case FID_DDCE:
					Pro.send_array(fci_ddce);
					break;
				case FID_0013:
					Pro.send_array(fci_0013);
					break;
				case FID_0016:
					Pro.send_array(fci_0016);
					break;
				case FID_EEEE:
					Pro.send_array(fci_eeee);
					break;
				case FID_5044:
					Pro.send_array(fci_5044);
					break;
				case FID_0033:
					Pro.send_array(fci_0033);
					break;
				default:
					Pro.throwIt(ISO7816.SW_FILE_NOT_FOUND);
				}
			}
			break;
		case ISO7816.INS_READ_BINARY:
			short offset = Util.makeShort(p1, p2);
			len = apdu.setOutgoing();
			if (runtime_fields[selectedfile] == FID_AACE) {
				Pro.send_array(authcert, offset, len);
			} else if (runtime_fields[selectedfile] == FID_DDCE) {
				Pro.send_array(signcert, offset, len);
			} else {
				Pro.throwIt(ISO7816.SW_FILE_INVALID);
			}
			break;
		case ISO7816.INS_READ_RECORD:
			byte recno = p1;
			if (runtime_fields[selectedfile] == FID_5044) {
				byte[] src = pd.rec2field(recno);
				if (src == null) {
					Pro.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				}
				Pro.send_array(src);
			} else if (runtime_fields[selectedfile] == FID_0016) {
				if (recno == (byte) 1) {
					Pro.send_array(mf_0016_1);
				} else if (recno == (byte) 2) {
					Pro.send_array(mf_0016_2);
				} else if (recno == (byte) 3) {
					Pro.send_array(mf_0016_3);
				} else {
					Pro.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				}
			} else if (runtime_fields[selectedfile] == FID_0013) {
				if (recno == (byte) 1) {
					Pro.send_array(eeee_0013_1);
				} else if (recno == (byte) 2) {
					Pro.send_array(eeee_0013_2);
				} else if (recno == (byte) 3) {
					Pro.send_array(eeee_0013_3);
				} else if (recno == (byte) 4) {
					Pro.send_array(eeee_0013_4);
				} else {
					Pro.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				}
			} else if (runtime_fields[selectedfile] == FID_0033) {
				if (recno == (byte) 1) {
					Pro.send_array(eeee_0033_1);
				} else {
					Pro.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
				}
			} else
				Pro.throwIt(ISO7816.SW_FILE_INVALID);
			break;
			// Above is enough to show a "valid card" in qesteidutil/pkcs15-tool
		case ISO7816.INS_VERIFY:
			// We don't use PIN codes, so anything goes
			len = apdu.setIncomingAndReceive();
			Pro.throwIt(ISO7816.SW_NO_ERROR);
			break;
		case ISO7816.INS_CHANGE_REFERENCE_DATA:
			// We don't use PIN codes, so anything goes
			Pro.throwIt(ISO7816.SW_NO_ERROR);
			break;
		case ISO7816.INS_RESET_RETRY_COUNTER:
			// We don't use PIN codes, so anything goes
			Pro.throwIt(ISO7816.SW_NO_ERROR);
			break;
			// The following commands do actual crypto
		case ISO7816.INS_MANAGE_SECURITY_ENVIRONMENT:
			// Internal state is implicitly known
			Pro.throwIt(ISO7816.SW_NO_ERROR);
			break;
		case ISO7816.INS_INTERNAL_AUTHENTICATE:
			// We sign the incoming data with authentication key
			len = apdu.setIncomingAndReceive();
			rsa.init(auth.getPrivate(), Cipher.MODE_ENCRYPT);
			len2 = rsa.doFinal(buffer, ISO7816.OFFSET_CDATA, len, ram, (short) 0);
			Pro.send_array(ram, (short)0, len2);
			break;
		case ISO7816.INS_PERFORM_SECURITY_OPERATION:
			len = apdu.setIncomingAndReceive();
			// Sign and decrypt
			short op = Util.makeShort(p1, p2);
			if (op == (short)0x9E9A) { // sign
				rsa.init(sign.getPrivate(), Cipher.MODE_ENCRYPT);
				len2 = rsa.doFinal(buffer, ISO7816.OFFSET_CDATA, len, ram, (short) 0);
				Pro.send_array(ram, (short)0, len2);
			} else if (op == (short)0x8086) { //decrypt
				if (buffer[0] == 0x10) {
					// Skip initial 0
					short len1 = Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA+1), ram, (short)2, (short)(len - 1));
					// Store offset to pos0
					Util.setShort(ram, (short) 0, len1);
				} else {
					// Concatenate
					len2 = Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, ram, Util.makeShort(ram[0], ram[1]), len);
					// Shift back by two
					len = Util.arrayCopyNonAtomic(ram, (short)2, ram, (short)0, (short) (len2-2));
					// Decrypt directly into APDU buffer
					rsa.init(auth.getPrivate(), Cipher.MODE_DECRYPT);
					len2 = rsa.doFinal(ram, (short) 0, len, buffer, (short) 0);
					Pro.send((short)0, len2);
				}
			} else {
				Pro.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}
			break;
		default:
			Pro.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void process_mock_commands(APDU apdu, byte[] buffer) {
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];

		short len = 0;
		short offset = 0;
		byte [] src = null;
		byte i = 0;
		KeyPair kp = null;

		// set/get the values
		switch (buffer[ISO7816.OFFSET_INS]) {
		case 0x02: // Store certificate
			len = apdu.setIncomingAndReceive();
			offset = Util.makeShort(buffer[ISO7816.OFFSET_CDATA], buffer[ISO7816.OFFSET_CDATA + 1]);
			if (p1 == 0x01) {
				Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA + 2), authcert, offset, (short) (len - 2));
			} else if (p1 == 0x02) {
				Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA + 2), signcert, offset, (short) (len - 2));
			} else
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		case 0x05: // PIN codes
			if (p2 == 0x00) { // puk
				src = puk;
			} else if (p2 == 0x01) {
				src = pin1;
			} else if (p2 == 0x02) {
				src = pin2;
			} else
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			if (buffer[ISO7816.OFFSET_LC] == 0x00) { // get
				Pro.send_array(src, (short) 0, (short) (src[0]+1));
			} else { //set
				len = apdu.setIncomingAndReceive();
				Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_LC, src, (short) 0, len);
				src[0] = (byte) len;
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}